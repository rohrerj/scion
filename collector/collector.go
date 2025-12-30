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

package collector

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/collector/db"
	"github.com/scionproto/scion/pkg/experimental/pot/monitor"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/proto/proof_of_forwarding"
	"github.com/scionproto/scion/private/topology"
)

type Collector struct {
}

func (c *Collector) InitCollector(errCtx context.Context, connectionString string, routers []topology.BRInfo) error {
	db_inserter, err := db.SetupDataInserter(errCtx, 1000, 100, connectionString)
	if err != nil {
		return err
	}
	frame_length := monitor.Window_length * time.Duration(monitor.Num_Windows_Per_Frame)
	ticker := time.NewTicker(frame_length)
	t := <-ticker.C
	frame_id := (((monitor.WindowIndex(t)+monitor.Num_Windows_Per_Frame)%monitor.Num_windows)/monitor.Num_Windows_Per_Frame + 2) % monitor.Num_Frames
loop:
	for {
		t := <-ticker.C
		select {
		case <-errCtx.Done():
			break loop
		default:
		}
		frame_id = (frame_id + 1) % monitor.Num_Frames
		log.Debug("frame_id", "id", frame_id)
		for _, router := range routers {
			go func(addr *net.TCPAddr, collectionTime time.Time, frame_id int) {
				ctx, cancelF := context.WithTimeout(errCtx, time.Second*2)
				defer cancelF()
				dialer := libgrpc.TCPDialer{}
				conn, err := dialer.Dial(ctx, addr)
				if err != nil {
					log.Error("Error dialing monitor", "addr", addr, "err", err)
					return
				}
				defer conn.Close()
				client := proof_of_forwarding.NewMonitorServiceClient(conn)
				resp, err := client.Collect(ctx, &proof_of_forwarding.CollectRequest{
					FrameId: uint32(frame_id),
				})
				if err != nil {
					log.Error("Error collecting from monitor", "addr", addr, "err", err)
					return
				}

				for _, entry := range resp.Entries {
					db_inserter.Data <- &db.Row{
						Time:              collectionTime.Add(-frame_length),
						TimeWindow:        int16(entry.Index),
						Ingress:           int16(entry.Ingress),
						Egress:            int16(entry.Egress),
						Data:              [32]byte(entry.Bucket),
						Counter:           entry.Counter,
						IsIngress:         entry.IsIngress,
						SourceIAAggregate: entry.SourceIaAggregate,
					}

				}
			}(router.MonitorAddr, t, frame_id)
		}
	}
	return nil
}
