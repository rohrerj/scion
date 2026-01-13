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

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/experimental/pot/locator"
	"github.com/scionproto/scion/pkg/experimental/pot/monitor"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/flag"
)

func newLocator(pather CommandPather) *cobra.Command {
	var envFlags flag.SCIONEnvironment
	var flags struct {
		timeout  time.Duration
		logLevel string
		noColor  bool
		tracer   string
		format   string
	}

	type packet_path struct {
		Hops []locator.Hop
	}

	var cmd = &cobra.Command{
		Use:     "locator <remote> <dropIA>",
		Short:   "Locates dropped packet",
		Args:    cobra.ExactArgs(2),
		Example: fmt.Sprintf(`  %[1]s locator '`, pather.CommandPath()),
		Long: `'locator' sends a SCION packet from local IA to remote IA that gets dropped at 'dropIA', which has to be an on-path IA,
		and then tries to use the locator logic to verify whether the correct drop location was identified`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancelF := context.WithTimeout(context.Background(), flags.timeout)
			defer cancelF()
			if err := app.SetupLog(flags.logLevel); err != nil {
				return serrors.WrapStr("setting up logging", err)
			}
			remote, err := addr.ParseAddr(args[0])
			if err != nil {
				return serrors.WrapStr("parsing remote", err)
			}
			dropIA, err := addr.ParseIA(args[1])
			if err != nil {
				return serrors.WrapStr("parsing dropIA", err)
			}
			if err := envFlags.LoadExternalVars(); err != nil {
				return err
			}
			daemonAddr := envFlags.Daemon()
			sd, err := daemon.NewService(daemonAddr).Connect(ctx)
			if err != nil {
				return serrors.WrapStr("connecting to the SCION Daemon", err, "addr", daemonAddr)
			}
			defer sd.Close()
			localIA, err := sd.LocalIA(ctx)
			if err != nil {
				return err
			}
			localAddr2, err := net.ResolveUDPAddr("udp", daemonAddr)
			if err != nil {
				return err
			}
			localAddr := &net.UDPAddr{
				IP:   localAddr2.IP,
				Port: 0,
				Zone: localAddr2.Zone,
			}
			n := snet.SCIONNetwork{
				Topology: sd,
			}
			packetConn, err := n.OpenRaw(ctx, localAddr)
			if err != nil {
				return err
			}
			defer packetConn.Close()
			remoteHost, err := addr.ParseHost(remote.Host.String())
			if err != nil {
				return err
			}
			net.ResolveUDPAddr("udp", localAddr.String())
			localHost, err := addr.ParseHost(localAddr.IP.String())
			if err != nil {
				return err
			}
			paths, err := sd.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{})
			if err != nil {
				return err
			}
			var path snet.Path
			found := false
			for _, p := range paths {
				for _, interfaces := range p.Metadata().Interfaces {
					if interfaces.IA == dropIA {
						path = p
						found = true
						break
					}
				}
			}
			if !found {
				return serrors.New("no path found that contains dropAS")
			}
			tClass := uint8(dropIA)
			send_time := time.Now()
			pkt := snet.Packet{
				PacketInfo: snet.PacketInfo{
					Destination: addr.Addr{
						IA:   remote.IA,
						Host: remoteHost,
					},
					Source: addr.Addr{
						IA:   localIA,
						Host: localHost,
					},
					Path:         path.Dataplane(),
					Payload:      snet.UDPPayload{},
					TrafficClass: &tClass,
					SendTime:     &send_time,
				},
			}
			m := &monitor.Monitor{
				NewHasher:  sha256.New,
				NewSampler: func() monitor.Sampler { return &monitor.FirstAndLastSampler{} },
			}
			fmt.Println("flowid", monitor.WindowIndex(send_time))
			monitor_worker := m.NewMonitorWorker()

			err = packetConn.WriteTo(&pkt, path.UnderlayNextHop())
			if err != nil {
				return err
			}
			// now wait 10 seconds
			time.Sleep(10 * time.Second)
			err = monitor_worker.HashPacket(pkt.Bytes)
			if err != nil {
				return err
			}
			// now try to start the locator workflow
			l := locator.NewLocator(sd, send_time, localIA, localAddr)
			dropLocations, err := l.LocatePacketDrop(ctx, &locator.PacketDrop{
				Path:       path,
				PacketHash: monitor_worker.HashBuffer,
			})
			if err != nil {
				return err
			}
			fmt.Println("Found drop location:", dropLocations)
			return nil
		}}

	envFlags.Register(cmd.Flags())
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 20*time.Second, "Timeout")
	cmd.Flags().StringVar(&flags.format, "format", "human",
		"Specify the output format (human|json|yaml)")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "", "Tracing agent address")
	return cmd
}
