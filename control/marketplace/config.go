package marketplace

import (
	"io"

	"github.com/scionproto/scion/private/config"
)

type Config struct {
	Token string `toml:"token,omitempty"`
}

// Sample implements [config.Sampler].
func (c *Config) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {

}

// Validate implements [config.Validator].
func (c *Config) Validate() error {
	return nil
}

func (c *Config) InitDefaults() {
}
