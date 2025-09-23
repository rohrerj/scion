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

	"github.com/scionproto/scion/collector"
	"github.com/scionproto/scion/collector/config"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/launcher"
	"github.com/scionproto/scion/private/topology"
)

var globalCfg config.Config

func main() {
	application := launcher.Application{
		TOMLConfig: &globalCfg,
		ShortName:  "SCION Collector",
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
	all_routers, err := topo.Get().BorderRouters()
	if err != nil {
		return err
	}
	collector := collector.Collector{}
	if globalCfg.Collector.DBConnectionString == "" {
		log.Error("Collector DBConnectionString unset")
		return nil
	}
	collector.InitCollector(globalCfg.Collector.DBConnectionString, all_routers)
	return nil
}
