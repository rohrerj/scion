// Copyright 2026 ETH Zurich
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

package endhost

import (
	"context"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

func NewConnector(ctx context.Context, api string) (*Connector, error) {
	trustService := NewTrustService(api)
	c := &Connector{
		UnderlayService: NewUnderlayService(api),
		TrustService:    trustService,
	}
	topo, err := c.loadTopology(ctx)
	if err != nil {
		return nil, err
	}
	c.PathService = NewPathService(api, topo, trustService)
	return c, nil
}

type Connector struct {
	UnderlayService *UnderlayService
	PathService     *PathService
	TrustService    *TrustService
	// cached values
	underlays  *Underlays
	interfaces map[uint16]netip.AddrPort
}

func (c *Connector) GetTopology() snet.Topology {
	return c.PathService.topo
}

func (c *Connector) loadTopology(ctx context.Context) (snet.Topology, error) {
	topo := snet.Topology{}
	allUnderlays, err := c.UnderlayService.ListUnderlays(ctx, nil)
	if err != nil {
		return topo, err
	}
	c.underlays = allUnderlays
	// TODO: add support for snap
	if c.underlays.Udp == nil || len(c.underlays.Udp.Routers) == 0 {
		return topo, serrors.New("Local IA cannot be determined without a UDP underlay present")
	}
	// for the moment we just take the first router to determine the local IA
	firstRouter := c.underlays.Udp.Routers[0]
	topo.LocalIA = addr.IA(firstRouter.IsdAs)
	topo.PortRange = snet.TopologyPortRange{
		Start: uint16(firstRouter.DispatchedPortStart),
		End:   uint16(firstRouter.DispatchedPortEnd),
	}
	c.interfaces = make(map[uint16]netip.AddrPort)
	for _, router := range c.underlays.Udp.Routers {
		addr, err := netip.ParseAddrPort(router.Address)
		if err != nil {
			return topo, err
		}
		for _, inf := range router.Interfaces {
			c.interfaces[uint16(inf)] = addr
		}
	}
	topo.Interface = func(u uint16) (netip.AddrPort, bool) {
		addr, ok := c.interfaces[u]
		return addr, ok
	}
	return topo, nil
}
