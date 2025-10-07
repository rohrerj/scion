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
	"net/netip"

	"github.com/scionproto/scion/bucket_store/config"
	"github.com/scionproto/scion/bucket_store/server"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app"
	infraenv "github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/app/launcher"
	"github.com/scionproto/scion/private/topology"
	"golang.org/x/sync/errgroup"
)

var globalCfg config.Config

func main() {
	application := launcher.Application{
		TOMLConfig: &globalCfg,
		ShortName:  "Bucket Store",
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
	localAddr, err := topo.Get().Anycast(addr.SvcBS)
	if err != nil {
		log.Error("error", "err", err)
		return err
	}
	log.Debug("Bucket Store", "localAddr", localAddr, "publicAddr", topo.BucketStoreAddress(globalCfg.General.ID))
	g, errCtx := errgroup.WithContext(ctx)
	var cleanup app.Cleanup
	g.Go(func() error {
		defer log.HandlePanic()
		<-errCtx.Done()
		return cleanup.Do()
	})
	g.Go(func() error {
		defer log.HandlePanic()
		nc := infraenv.NetworkConfig{
			IA:          topo.IA(),
			Public:      topo.BucketStoreAddress(globalCfg.General.ID),
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
		s, err := server.NewLostPacketService(localAddr)
		if err != nil {
			return err
		}
		return s.Serve(quicStack.Listener)
	})

	return g.Wait()
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
