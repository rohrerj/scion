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
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/proto/proof_of_forwarding"
	"google.golang.org/grpc"
)

type BucketStoreServer struct {
	DataQuerier *db.DataQuerier
}

func (l *BucketStoreServer) Query(ctx context.Context, req *proof_of_forwarding.QueryRequest) (*proof_of_forwarding.QueryResponse, error) {
	frame_length := monitor.Window_length * time.Duration(monitor.Num_Windows_Per_Frame)
	window_index := monitor.WindowIndex(req.SendTime.AsTime())
	start := req.SendTime.AsTime().UTC().Add(-frame_length)
	end := req.SendTime.AsTime().UTC().Add(frame_length)
	log.Debug("Query request", "start", start, "end", end, "window_index", window_index)
	rows, err := l.DataQuerier.Query(ctx, start, end, window_index)
	if err != nil {
		log.Error("error", "err", err)
		return nil, err
	}
	res := &proof_of_forwarding.QueryResponse{
		Entries: make([]*proof_of_forwarding.QueryResponseEntry, 0, len(rows)),
		Index:   uint32(window_index),
	}
	for _, row := range rows {
		data := make([]byte, 32)
		copy(data, row.Data[:])
		res.Entries = append(res.Entries, &proof_of_forwarding.QueryResponseEntry{
			Ingress:           uint32(row.Ingress),
			Egress:            uint32(row.Egress),
			Bucket:            data,
			Counter:           row.Counter,
			IsIngress:         row.IsIngress,
			SourceIaAggregate: row.SourceIAAggregate,
		})
	}
	return res, nil
}

func NewBucketStoreService(server *grpc.Server, dataQuerier *db.DataQuerier) (*grpc.Server, error) {
	proof_of_forwarding.RegisterBucketStoreServer(server, &BucketStoreServer{
		DataQuerier: dataQuerier,
	})
	return server, nil
}
