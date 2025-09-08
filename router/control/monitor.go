// Copyright 2025 ETH Zürich
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

package control

import (
	"net"

	"github.com/scionproto/scion/pkg/experimental/pot/monitor"
	"github.com/scionproto/scion/pkg/log"
)

func StartMonitorService(m *monitor.Monitor, monitorAddr *net.TCPAddr) error {
	log.Debug("Starting monitor server", "addr", monitorAddr)
	lis, err := net.ListenTCP("tcp", monitorAddr)
	if err != nil {
		return err
	}
	server, err := monitor.NewMonitorService(m, monitorAddr)
	if err != nil {
		return err
	}
	err = server.Serve(lis)
	return err
}
