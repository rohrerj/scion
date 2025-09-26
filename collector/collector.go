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
	ticker := time.NewTicker(monitor.Window_length)
loop:
	for {
		t := <-ticker.C
		select {
		case <-errCtx.Done():
			break loop
		default:
		}
		time_window := (monitor.WindowIndex(t) - monitor.Num_windows/2 + monitor.Num_windows) % monitor.Num_windows
		for _, router := range routers {
			go func(addr *net.TCPAddr, collectionTime time.Time, time_window uint8) {
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
					TimeWindow: uint32(time_window),
				})
				if err != nil {
					log.Error("Error collecting from monitor", "addr", addr, "err", err)
					return
				}

				for _, entry := range resp.Entries {
					db_inserter.Data <- &db.Row{
						Time:       collectionTime,
						TimeWindow: int16(time_window),
						Ingress:    int16(entry.Ingress),
						Egress:     int16(entry.Egress),
						Data:       [32]byte(entry.Bucket),
					}
				}
			}(router.MonitorAddr, t, time_window)
		}
	}
	return nil
}
