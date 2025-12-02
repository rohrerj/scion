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
	"time"

	"github.com/scionproto/scion/bucket_store/db"
	"github.com/scionproto/scion/pkg/experimental/pot/monitor"
	"github.com/scionproto/scion/pkg/proto/proof_of_forwarding"
	"google.golang.org/grpc"
)

type BucketStoreServer struct {
	DataQuerier *db.DataQuerier
}

func (l *BucketStoreServer) Query(ctx context.Context, req *proof_of_forwarding.QueryRequest) (*proof_of_forwarding.QueryResponse, error) {
	frame_length := monitor.Window_length * time.Duration(monitor.Num_Windows_Per_Frame)
	window_index := monitor.GetWindowIndexForTime(req.SendTime.AsTime())
	start := req.SendTime.AsTime().Add(-frame_length)
	end := req.SendTime.AsTime().Add(frame_length)
	rows, err := l.DataQuerier.Query(ctx, start, end, window_index)
	if err != nil {
		return nil, err
	}
	res := &proof_of_forwarding.QueryResponse{
		Entries: make([]*proof_of_forwarding.QueryResponseEntry, 0, len(rows)),
		Index:   uint32(window_index),
	}
	for _, row := range rows {
		var egress uint32
		if row.Egress != nil {
			egress = uint32(*row.Egress)
		}
		res.Entries = append(res.Entries, &proof_of_forwarding.QueryResponseEntry{
			Ingress:   uint32(row.Ingress),
			Egress:    &egress,
			Bucket:    row.Data[:],
			Counter:   row.Counter,
			IsIngress: row.IsIngress,
		})
	}
	return res, nil
}

func (l *BucketStoreServer) ReportDrop(ctx context.Context, req *proof_of_forwarding.DropRequest) (*proof_of_forwarding.DropResponse, error) {
	return nil, nil
}

func NewBucketStoreService(server *grpc.Server, dataQuerier *db.DataQuerier) (*grpc.Server, error) {
	proof_of_forwarding.RegisterBucketStoreServer(server, &BucketStoreServer{
		DataQuerier: dataQuerier,
	})
	return server, nil
}
