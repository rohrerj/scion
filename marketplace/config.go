// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package marketplace

import (
	"io"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/env"
)

type Config struct {
	General     env.General       `toml:"general,omitempty"`
	Logging     log.Config        `toml:"log,omitempty"`
	Marketplace MarketplaceConfig `toml:"marketplace,omitempty"`
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Logging,
		&cfg.Marketplace,
	)
}
func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Logging,
		&cfg.Marketplace,
	)
}
func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {

}

type MarketplaceConfig struct {
	APIAddr     string `toml:"api_addr,omitempty"`
	AccountAddr string `toml:"account_addr,omitempty"`
}

func (cfg *MarketplaceConfig) InitDefaults() {
	if cfg.APIAddr == "" {
		cfg.APIAddr = "localhost:8888"
	}
	if cfg.AccountAddr == "" {
		cfg.AccountAddr = "localhost:8889"
	}
}
func (cfg *MarketplaceConfig) Validate() error {
	return nil
}
func (cfg *MarketplaceConfig) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {

}
