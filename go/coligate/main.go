// Copyright 2022 ETH Zurich
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

	"github.com/scionproto/scion/go/coligate/processing"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/app/launcher"
	"github.com/scionproto/scion/go/pkg/coligate/config"
	"golang.org/x/sync/errgroup"
)

func main() {
	var cfg config.Config
	application := launcher.Application{
		TOMLConfig: &cfg,
		ShortName:  "SCION COLIBRI Gateway",
		Main: func(ctx context.Context) error {
			return realMain(ctx, &cfg)
		},
	}
	application.Run()
}

func realMain(ctx context.Context, cfg *config.Config) error {
	topo, err := topology.NewLoader(topology.LoaderCfg{
		File:      cfg.General.Topology(),
		Reload:    app.SIGHUPChannel(ctx),
		Validator: &topology.DefaultValidator{},
		// Metrics: , // TODO(justin) add observability to the gateway
	})
	if err != nil {
		return serrors.WrapStr("creating topology loader", err)
	}
	g, errCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer log.HandlePanic()
		return topo.Run(errCtx)
	})

	var cleanup app.Cleanup

	var egressMapping map[uint16]*net.UDPAddr = make(map[uint16]*net.UDPAddr)

	for ifid, info := range topo.InterfaceInfoMap() {
		egressMapping[uint16(ifid)] = info.InternalAddr
	}

	serverAddr := &snet.UDPAddr{
		IA:   topo.IA(),
		Host: topo.ColibriGatewayServiceAddress(cfg.General.ID),
	}

	//init
	colibriServiceAddresses := topo.ColibriServiceAddresses()
	if len(colibriServiceAddresses) < 1 {
		return serrors.New("No instance of colibri service found in local AS.")
	}
	err = processing.Init(ctx, &cfg.Coligate, &cleanup, &egressMapping, serverAddr, colibriServiceAddresses[0], g)
	if err != nil {
		return err
	}

	// cleanup when exit
	g.Go(func() error {
		defer log.HandlePanic()
		<-errCtx.Done()
		return cleanup.Do()
	})
	return g.Wait()
}
