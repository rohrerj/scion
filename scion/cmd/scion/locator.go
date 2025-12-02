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
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/experimental/pot/locator"
	"github.com/scionproto/scion/pkg/private/serrors"
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
		Use:     "locator identifier [time] [packet_hash] [path]",
		Short:   "Locates dropped packet",
		Args:    cobra.RangeArgs(3, 3),
		Example: fmt.Sprintf(`  %[1]s locator '`, pather.CommandPath()),
		Long:    `'locator' identifies which AS was responsible of the packet drop for a particular packet`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancelF := context.WithTimeout(context.Background(), flags.timeout)
			defer cancelF()
			if err := app.SetupLog(flags.logLevel); err != nil {
				return serrors.WrapStr("setting up logging", err)
			}
			packet_send_time, err := time.Parse(time.RFC3339, args[0])
			if err != nil {
				return err
			}
			packet_hash := args[1]
			serialized_path := args[2]
			var usedPath packet_path
			err = json.Unmarshal([]byte(serialized_path), &usedPath)
			if err != nil {
				return err
			}

			daemonAddr := envFlags.Daemon()
			daemonService := &daemon.Service{
				Address: daemonAddr,
			}
			sd, err := daemonService.Connect(ctx)
			if err != nil {
				return serrors.WrapStr("connecting to the SCION Daemon", err, "addr", daemonAddr)
			}
			defer sd.Close()
			localIA, err := sd.LocalIA(ctx)
			if err != nil {
				return err
			}
			localAddr, err := net.ResolveUDPAddr("udp", daemonAddr)
			if err != nil {
				return err
			}
			l := locator.NewLocator(sd, packet_send_time, localIA, localAddr)
			dropLocations, err := l.LocatePacketDrop(ctx, &locator.PacketDrop{
				SendTime: packet_send_time,
				Path:     usedPath.Hops,
				//TODO: this is probably in base64 and has to be changed back to bytes
				PacketHash: []byte(packet_hash),
			})
			if err != nil {
				return err
			}
			fmt.Println("Found drop location:", dropLocations)
			return nil
		}}

	envFlags.Register(cmd.Flags())
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 5*time.Second, "Timeout")
	cmd.Flags().StringVar(&flags.format, "format", "human",
		"Specify the output format (human|json|yaml)")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "", "Tracing agent address")
	return cmd
}
