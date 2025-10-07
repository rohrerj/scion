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
	"fmt"
	"time"

	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/flag"
	"github.com/spf13/cobra"
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

	var cmd = &cobra.Command{
		Use:     "locator identifier [time] [packet_hash]",
		Short:   "Locates dropped packet",
		Args:    cobra.RangeArgs(2, 2),
		Example: fmt.Sprintf(`  %[1]s locator '`, pather.CommandPath()),
		Long:    `'locator' identifies which AS was responsible of the packet drop for a particular packet`,
		RunE: func(cmd *cobra.Command, args []string) error {
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
