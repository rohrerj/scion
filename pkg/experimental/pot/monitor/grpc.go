// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package monitor

import (
	"context"
	"math/big"
	"net"
	"slices"

	"google.golang.org/grpc"

	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/proto/proof_of_forwarding"
)

type MonitorServer struct {
	monitor         *Monitor
	localInterfaces []uint16
}

func (m *MonitorServer) Collect(ctx context.Context, req *proof_of_forwarding.CollectRequest) (*proof_of_forwarding.CollectResponse, error) {
	m.monitor.mtx.Lock()
	defer m.monitor.mtx.Unlock()
	buckets := map[uint64]*Bucket{}
	frame_id := req.FrameId
	fromTimeWindow := Num_Windows_Per_Frame * frame_id
	toTimeWindow := Num_Windows_Per_Frame * (frame_id + 1)
	responseEntries := make([]*proof_of_forwarding.CollectResponseEntry, 0, 128)
	log.Debug("time window", "from", fromTimeWindow, "to", toTimeWindow, "frameid", frame_id)
	for time_window := fromTimeWindow; time_window < toTimeWindow; time_window++ {
		for _, worker := range m.monitor.workers {
			for key, bucket := range worker.Buckets[time_window] {
				current_bucket, ok := buckets[key]
				if ok {
					err := worker.Aggregate(current_bucket, &bucket)
					if err != nil {
						return nil, err
					}
				} else {
					var newBigInt big.Int
					newBigInt.Set(bucket.SourceIAAggregate)
					current_bucket := &Bucket{
						Data:              make([]byte, len(bucket.Data)),
						Counter:           bucket.Counter,
						SourceIAAggregate: &newBigInt,
					}
					copy(current_bucket.Data, bucket.Data)
					buckets[key] = current_bucket
				}
			}
			worker.ClearBuckets(int(time_window))
		}
		for key, bucket := range buckets {
			ingress := uint16(key >> 16)
			isLocalIngress := slices.Contains(m.localInterfaces, ingress)
			egress := uint32(key & 0xffff)
			var entry *proof_of_forwarding.CollectResponseEntry
			entry = &proof_of_forwarding.CollectResponseEntry{
				Ingress:           uint32(ingress),
				Egress:            egress,
				Bucket:            bucket.Data,
				Counter:           bucket.Counter,
				Index:             time_window,
				IsIngress:         isLocalIngress,
				SourceIaAggregate: bucket.SourceIAAggregate.String(),
			}
			responseEntries = append(responseEntries, entry)
			if slices.Contains(m.localInterfaces, uint16(egress)) {
				// in case the current border router is both ingress and egress border router
				entry2 := &proof_of_forwarding.CollectResponseEntry{
					Ingress:           uint32(ingress),
					Egress:            egress,
					Bucket:            bucket.Data,
					Counter:           bucket.Counter,
					Index:             time_window,
					IsIngress:         !isLocalIngress,
					SourceIaAggregate: bucket.SourceIAAggregate.String(),
				}
				responseEntries = append(responseEntries, entry2)
			}
		}
	}
	res := &proof_of_forwarding.CollectResponse{
		Entries: responseEntries,
	}
	return res, nil
}

func NewMonitorService(m *Monitor, addr *net.TCPAddr, localInterfaces []uint16) (*grpc.Server, error) {
	server := grpc.NewServer(
		libgrpc.UnaryServerInterceptor(),
		libgrpc.DefaultMaxConcurrentStreams(),
	)
	proof_of_forwarding.RegisterMonitorServiceServer(server, &MonitorServer{
		monitor:         m,
		localInterfaces: localInterfaces,
	})
	return server, nil
}
