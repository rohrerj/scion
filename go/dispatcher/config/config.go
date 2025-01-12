// Copyright 2018 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

// Package config contains the configuration of the SCION dispatcher.
package config

import (
	"fmt"
	"io"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/api"
)

var _ config.Config = (*Config)(nil)

type Config struct {
	Features   env.Features `toml:"features,omitempty"`
	Logging    log.Config   `toml:"log,omitempty"`
	Metrics    env.Metrics  `toml:"metrics,omitempty"`
	API        api.Config   `toml:"api,omitempty"`
	Dispatcher Dispatcher   `toml:"dispatcher,omitempty"`
}

// Dispatcher contains the dispatcher specific config.
type Dispatcher struct {
	config.NoDefaulter
	// ID of the Dispatcher (required)
	ID string `toml:"id,omitempty"`
	// ApplicationSocket is the local API socket (default /run/shm/dispatcher/default.sock)
	ApplicationSocket string `toml:"application_socket,omitempty"`
	// Socket file permissions when created; read from octal. (default 0770)
	SocketFileMode util.FileMode `toml:"socket_file_mode,omitempty"`
	// UnderlayPort is the native port opened by the dispatcher (default 30041)
	UnderlayPort int `toml:"underlay_port,omitempty"`
	// DeleteSocket specifies whether the dispatcher should delete the
	// socket file prior to attempting to create a new one.
	DeleteSocket bool `toml:"delete_socket,omitempty"`
}

func (cfg *Dispatcher) Validate() error {
	if cfg.ApplicationSocket == "" {
		cfg.ApplicationSocket = reliable.DefaultDispPath
	}
	if cfg.SocketFileMode == 0 {
		cfg.SocketFileMode = reliable.DefaultDispSocketFileMode
	}
	if cfg.UnderlayPort == 0 {
		cfg.UnderlayPort = topology.EndhostPort
	}
	if cfg.ID == "" {
		return serrors.New("id must be set")
	}
	return nil
}

func (cfg *Dispatcher) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(dispSample, idSample))
}

func (cfg *Dispatcher) ConfigName() string {
	return "dispatcher"
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Dispatcher,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Dispatcher,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Dispatcher,
	)
}

func (cfg *Config) ConfigName() string {
	return "dispatcher_config"
}
