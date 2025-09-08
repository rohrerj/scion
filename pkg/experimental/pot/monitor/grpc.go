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
	"net"

	"google.golang.org/grpc"

	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/proto/proof_of_forwarding"
)

type MonitorServer struct {
	monitor *Monitor
}

func (m *MonitorServer) Collect(ctx context.Context, req *proof_of_forwarding.CollectRequest) (*proof_of_forwarding.CollectResponse, error) {
	m.monitor.mtx.Lock()
	defer m.monitor.mtx.Unlock()
	buckets := map[uint32]Bucket{}
	time_window := req.TimeWindow
	for _, worker := range m.monitor.workers {
		for key, bucket := range worker.Buckets[time_window] {
			current_bucket, ok := buckets[key]
			if ok {
				err := worker.Aggregate(current_bucket, bucket)
				if err != nil {
					return nil, err
				}
			} else {
				new_bucket := make([]byte, len(bucket))
				copy(new_bucket, bucket)
				buckets[key] = new_bucket
			}
		}
	}
	responseEntries := make([]*proof_of_forwarding.CollectResponseEntry, 0, len(buckets))
	for key, bucket := range buckets {
		ingress := uint16(key >> 16)
		egress := uint16(key)
		responseEntries = append(responseEntries, &proof_of_forwarding.CollectResponseEntry{
			Ingress: uint32(ingress),
			Egress:  uint32(egress),
			Bucket:  bucket,
		})
	}
	res := &proof_of_forwarding.CollectResponse{
		Entries: responseEntries,
	}
	return res, nil
}

func NewMonitorService(m *Monitor, addr *net.TCPAddr) (*grpc.Server, error) {
	server := grpc.NewServer(
		libgrpc.UnaryServerInterceptor(),
		libgrpc.DefaultMaxConcurrentStreams(),
	)
	proof_of_forwarding.RegisterMonitorServiceServer(server, &MonitorServer{
		monitor: m,
	})
	return server, nil
}
