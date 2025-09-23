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

package config

import (
	"io"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/env"
)

type Config struct {
	General   env.General     `toml:"general,omitempty"`
	Logging   log.Config      `toml:"log,omitempty"`
	Collector CollectorConfig `toml:"collector,omitempty"`
}

type CollectorConfig struct {
	DBConnectionString string `toml:"db,omitempty"`
}

func (cfg *Config) InitDefaults() {}

func (cfg *Config) Validate() error { return nil }

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {}
