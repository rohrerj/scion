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
	"time"

	"github.com/scionproto/scion/pkg/experimental/pot/monitor"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/proto/proof_of_forwarding"
	"github.com/scionproto/scion/private/topology"
)

type Collector struct {
}

func (c *Collector) InitCollector(routers []topology.BRInfo) error {
	ticker := time.NewTicker(monitor.Window_length)
	for {
		t := <-ticker.C
		time_window := (monitor.WindowIndex(t) - monitor.Num_windows/2 + monitor.Num_windows) % monitor.Num_windows
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		for _, router := range routers {
			dialer := libgrpc.TCPDialer{}
			conn, err := dialer.Dial(ctx, router.MonitorAddr)
			if err != nil {
				log.Error("Error dialing monitor", "addr", router.MonitorAddr, "err", err)
				continue
			}
			client := proof_of_forwarding.NewMonitorServiceClient(conn)
			resp, err := client.Collect(ctx, &proof_of_forwarding.CollectRequest{
				TimeWindow: uint32(time_window),
			})
			conn.Close()
			if err != nil {
				log.Error("Error dialing monitor", "addr", router.MonitorAddr, "err", err)
				continue
			}
			for _, entry := range resp.Entries {
				log.Debug("ENTRY", "src", router.MonitorAddr, "time_window", time_window, "ingress", entry.Ingress, "egress", entry.Egress, "bucket", entry.Bucket)
			}
		}
		cancelF()
	}
}
