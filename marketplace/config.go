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
