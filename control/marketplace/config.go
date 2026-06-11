package marketplace

import (
	"io"

	"github.com/scionproto/scion/private/config"
)

type Config struct {
	MarketplaceApi string `toml:"marketplace_api,omitempty"`
}

func (c *Config) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {

}

func (c *Config) Validate() error {
	return nil
}

func (c *Config) InitDefaults() {
	if c.MarketplaceApi == "" {
		c.MarketplaceApi = "https://localhost:8888"
	}
}
