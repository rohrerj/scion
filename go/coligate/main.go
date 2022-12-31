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
	/*"os"

	"runtime/pprof"
	"runtime/trace"*/

	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/go/coligate/processing"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/app/launcher"
	common "github.com/scionproto/scion/go/pkg/coligate"
	"github.com/scionproto/scion/go/pkg/coligate/config"
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
	metrics := common.NewMetrics()
	topo, err := topology.NewLoader(topology.LoaderCfg{
		File:      cfg.General.Topology(),
		Reload:    app.SIGHUPChannel(ctx),
		Validator: &topology.DefaultValidator{},
		Metrics:   metrics.NewTopologyLoader(),
	})
	if err != nil {
		return serrors.WrapStr("creating topology loader", err)
	}
	/*log.Info("XXX", "AS", topo.IA().String())
	if topo.IA().String() == "1-ff00:0:110" {
		os.RemoveAll("pprof")
		os.Mkdir("pprof", os.ModePerm)
		cpuFile, err := os.Create("pprof/coligateCPU.pb.gz")
		if err != nil {
			return err
		}
		heapFile, err := os.Create("pprof/coligateHeap.pb.gz")
		if err != nil {
			return err
		}
		allocsFile, err := os.Create("pprof/coligateAllocs.pb.gz")
		if err != nil {
			return err
		}
		traceFile, err := os.Create("pprof/coligateTrace.out")
		if err != nil {
			return err
		}
		err = pprof.StartCPUProfile(cpuFile)
		if err != nil {
			return err
		}
		err = trace.Start(traceFile)
		if err != nil {
			return err
		}
		defer func() {
			pprof.StopCPUProfile()
			pprof.Lookup("allocs").WriteTo(allocsFile, 0)
			pprof.WriteHeapProfile(heapFile)
			trace.Stop()
			cpuFile.Close()
			heapFile.Close()
			allocsFile.Close()
			traceFile.Close()
		}()
	}*/

	g, errCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer log.HandlePanic()
		return topo.Run(errCtx)
	})

	closer, err := common.InitTracer(cfg.Tracing, cfg.General.ID)
	if err != nil {
		return serrors.WrapStr("initializing tracer", err)
	}
	defer closer.Close()

	var cleanup app.Cleanup

	err = processing.Init(ctx, cfg, &cleanup, g, topo, metrics)
	if err != nil {
		return err
	}

	g.Go(func() error {
		defer log.HandlePanic()
		return cfg.Metrics.ServePrometheus(errCtx)
	})

	// cleanup when exit
	g.Go(func() error {
		defer log.HandlePanic()
		<-errCtx.Done()
		return cleanup.Do()
	})
	return g.Wait()
}
