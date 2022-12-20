// Copyright 2020 ETH Zurich
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

	colconf "github.com/scionproto/scion/go/co/reservation/conf"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/pkg/storage"
)

// ColibriConfig is the root configuration for all things reservation.
type ColibriConfig struct {
	DB               storage.DBConfig      `toml:"db,omitempty"`
	Delta            float64               `toml:"delta"`
	CapacitiesFile   string                `toml:"capacities"`
	ReservationsFile string                `toml:"reservations"`
	Capacities       *colconf.Capacities   `toml:"omitempty"`
	Reservations     *colconf.Reservations `toml:"omitempty"`
	Gateways         []ColigateService     `toml:"gateways"`
}

type ColigateService struct {
	Name        string `toml:"name"`
	ControlAddr string `toml:"control_addr"` //the address for the grpc endpoint
}

func (cfg *ColibriConfig) Validate() error {
	var err error
	if cfg.CapacitiesFile != "" {
		cfg.Capacities, err = colconf.CapacitiesFromFile(cfg.CapacitiesFile)
		if err != nil {
			return err
		}
	}
	if cfg.ReservationsFile != "" {
		cfg.Reservations, err = colconf.ReservationsFromFile(cfg.ReservationsFile)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cfg *ColibriConfig) InitDefaults() {
	cfg.DB.InitDefaults()
	if cfg.DB.MaxOpenConns == 0 {
		cfg.DB.MaxOpenConns = 100
	}
	cfg.Delta = 0.8
	cfg.Capacities = &colconf.Capacities{}
	cfg.Reservations = &colconf.Reservations{}
}

func (cfg *ColibriConfig) Sample(dst io.Writer, _ config.Path, _ config.CtxMap) {
	config.WriteString(dst, colibriSample)
}

func (cfg *ColibriConfig) ConfigName() string {
	return "colibri"
}

const colibriSample = `
# COLIBRI service configuration sample
delta = 0.8
capacities_file = "capacities.json"
reservations_file = "reservations.json"
`
