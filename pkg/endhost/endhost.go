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
	"net"
	"net/netip"
	"strings"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/path/combinator"
)

func NewConnector(api string) *Connector {
	trustService := NewTrustService(api)
	return &Connector{
		underlayService: NewUnderlayService(api),
		pathService:     NewPathService(api, trustService),
		trustService:    trustService,
	}
}

type Connector struct {
	underlayService *UnderlayService
	pathService     *PathService
	trustService    *TrustService
	// cached values
	underlays  *Underlays
	interfaces map[uint16]netip.AddrPort
}

func (c *Connector) AllPaths(ctx context.Context, dst addr.IA, src addr.IA) ([]snet.Path, error) {
	interfacesToString := func(elems []snet.PathInterface) string {
		parts := make([]string, len(elems))
		for i, e := range elems {
			parts[i] = e.String()
		}
		return strings.Join(parts, "|")
	}

	paginator := c.pathService.NewPaginator(dst, src)
	paginator.pageSize = 64
	allPaths := make([]snet.Path, 0, 1)
	seen := make(map[string]struct{})
	for paginator.HasNext() {
		up, core, down, err := paginator.NextPage(ctx)
		if err != nil {
			return allPaths, err
		}
		combinedPaths := combinator.Combine(src, dst, up, core, down, false)
		for _, p := range combinedPaths {
			mapKey := interfacesToString(p.Metadata.Interfaces)
			if _, isSeen := seen[mapKey]; !isSeen {
				nextHopNetIpPort, ok := c.interfaces[uint16(p.Metadata.Interfaces[0].ID)]
				if !ok {
					return nil, serrors.New("nexthop cannot be determined")
				}
				addr := nextHopNetIpPort.Addr()
				nextHop := &net.UDPAddr{
					IP:   addr.AsSlice(),
					Port: int(nextHopNetIpPort.Port()),
					Zone: addr.Zone(),
				}
				path := snetpath.Path{
					Src:           p.Metadata.Interfaces[0].IA,
					Dst:           p.Metadata.Interfaces[len(p.Metadata.Interfaces)-1].IA,
					DataplanePath: p.SCIONPath,
					Meta:          p.Metadata,
					NextHop:       nextHop,
				}
				allPaths = append(allPaths, path)
				seen[mapKey] = struct{}{}
			}
		}
	}

	return allPaths, nil
}

func (c *Connector) Paths(ctx context.Context, dst addr.IA, src addr.IA) ([]snet.Path, error) {
	paginator := c.pathService.NewPaginator(dst, src)
	up, core, down, err := paginator.NextPage(ctx)
	if err != nil {
		return nil, err
	}
	combinedPaths := combinator.Combine(src, dst, up, core, down, false)
	paths := make([]snet.Path, 0, len(combinedPaths))
	for _, p := range combinedPaths {
		nextHopNetIpPort, ok := c.interfaces[uint16(p.Metadata.Interfaces[0].ID)]
		if !ok {
			return nil, serrors.New("nexthop cannot be determined")
		}
		addr := nextHopNetIpPort.Addr()
		nextHop := &net.UDPAddr{
			IP:   addr.AsSlice(),
			Port: int(nextHopNetIpPort.Port()),
			Zone: addr.Zone(),
		}
		path := snetpath.Path{
			Src:           p.Metadata.Interfaces[0].IA,
			Dst:           p.Metadata.Interfaces[len(p.Metadata.Interfaces)-1].IA,
			DataplanePath: p.SCIONPath,
			Meta:          p.Metadata,
			NextHop:       nextHop,
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func (c *Connector) LoadTopology(ctx context.Context) (snet.Topology, error) {
	topo := snet.Topology{}
	allUnderlays, err := c.underlayService.ListUnderlays(ctx, nil)
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
