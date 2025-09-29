// Copyright 2020 Anapaya Systems
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
	"net"
	"net/netip"

	"github.com/scionproto/scion/lost_packet_detector/config"
	"github.com/scionproto/scion/lost_packet_detector/server"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app"
	infraenv "github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/app/launcher"
	"github.com/scionproto/scion/private/topology"
)

var globalCfg config.Config

func main() {
	application := launcher.Application{
		TOMLConfig: &globalCfg,
		ShortName:  "Lost packet detector",
		Main:       realMain,
	}
	application.Run()
}

func realMain(ctx context.Context) error {
	topo, err := topology.NewLoader(topology.LoaderCfg{
		File:      globalCfg.General.Topology(),
		Reload:    app.SIGHUPChannel(ctx),
		Validator: &topology.DefaultValidator{},
	})
	if err != nil {
		return serrors.WrapStr("creating topology loader", err)
	}
	localAddr, err := topo.Get().Anycast(addr.SvcLP)
	if err != nil {
		return err
	}
	go func(addr *net.UDPAddr) error {
		defer log.HandlePanic()
		nc := infraenv.NetworkConfig{
			IA:          topo.IA(),
			Public:      topo.ControlServiceAddress(globalCfg.General.ID),
			QUIC:        infraenv.QUIC{},
			SVCResolver: topo,
			SCMPHandler: snet.DefaultSCMPHandler{},
			MTU:         topo.MTU(),
			Topology:    cpInfoProvider{topo: topo},
		}
		quicStack, err := nc.QUICStack()
		if err != nil {
			return serrors.WrapStr("initializing QUIC stack", err)
		}
		s, err := server.NewLostPacketService(addr)
		if err != nil {
			return err
		}
		return s.Serve(quicStack.Listener)
	}(localAddr)

	return nil
}

type cpInfoProvider struct {
	topo *topology.Loader
}

func (c cpInfoProvider) LocalIA(_ context.Context) (addr.IA, error) {
	return c.topo.IA(), nil
}

func (c cpInfoProvider) PortRange(_ context.Context) (uint16, uint16, error) {
	start, end := c.topo.PortRange()
	return start, end, nil
}

func (c cpInfoProvider) Interfaces(_ context.Context) (map[uint16]netip.AddrPort, error) {
	ifMap := c.topo.InterfaceInfoMap()
	ifsToUDP := make(map[uint16]netip.AddrPort, len(ifMap))
	for i, v := range ifMap {
		if i > (1<<16)-1 {
			return nil, serrors.New("invalid interface id", "id", i)
		}
		ifsToUDP[uint16(i)] = v.InternalAddr
	}
	return ifsToUDP, nil
}
