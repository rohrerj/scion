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
	/*if int(req.TimeWindow) > len(m.monitor.Buckets) {
		return nil, serrors.New("time window out of bounds")
	}
	buckets := m.monitor.Buckets[req.TimeWindow]
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
	return res, nil*/
	return nil, nil
}

type MonitorService struct{}

func NewMonitorService(m *Monitor, addr *net.TCPAddr) error {
	server := grpc.NewServer(
		libgrpc.UnaryServerInterceptor(),
		libgrpc.DefaultMaxConcurrentStreams(),
	)
	proof_of_forwarding.RegisterMonitorServiceServer(server, &MonitorServer{
		monitor: m,
	})
	lis, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	server.Serve(lis)
	return nil
}
