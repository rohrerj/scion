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

package server

import (
	"context"
	"net"

	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/proto/proof_of_forwarding"
	"google.golang.org/grpc"
)

type LostPacketDetectorServer struct {
}

func (l *LostPacketDetectorServer) Query(ctx context.Context, req *proof_of_forwarding.QueryRequest) (*proof_of_forwarding.QueryResponse, error) {
	res := &proof_of_forwarding.QueryResponse{}
	return res, nil
}

func NewLostPacketService(addr *net.UDPAddr) (*grpc.Server, error) {
	server := grpc.NewServer(
		grpc.Creds(libgrpc.PassThroughCredentials{}),
		libgrpc.UnaryServerInterceptor(),
		libgrpc.DefaultMaxConcurrentStreams(),
	)
	proof_of_forwarding.RegisterLostPacketDetectorServer(server, &LostPacketDetectorServer{})
	return server, nil
}
