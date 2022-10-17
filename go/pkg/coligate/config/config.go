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

package config

import (
	"io"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
)

type Config struct {
	General  env.General    `toml:"general,omitempty"`
	Logging  log.Config     `toml:"log,omitempty"`
	Metrics  env.Metrics    `toml:"metrics,omitempty"`
	Tracing  env.Tracing    `toml:"tracing,omitempty"`
	Coligate ColigateConfig `toml:"coligate,omitempty"`
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Tracing,
		&cfg.Coligate,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Coligate,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: "coligate"},
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Tracing,
		&cfg.Coligate,
	)
}
