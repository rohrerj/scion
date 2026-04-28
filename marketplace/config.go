package marketplace

import (
	"io"

	"github.com/scionproto/scion/private/config"
)

type Config struct {
	Addr string
}

func (cfg *Config) InitDefaults() {
	cfg.Addr = "https://localhost:8888"
}
func (cfg *Config) Validate() error {
	return nil
}
func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {

}
