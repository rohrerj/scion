// Copyright 2023 ETH Zurich
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
	"github.com/scionproto/scion/pkg/segment/extensions/fabrid"
	"io"
	"strings"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/config"
)

type FABRIDPolicy struct {
	IsLocalPolicy    bool                     `yaml:"local,omitempty"`
	LocalIdentifier  uint32                   `yaml:"local_identifier,omitempty"`
	LocalDescription string                   `yaml:"local_description,omitempty"`
	GlobalIdentifier uint32                   `yaml:"global_identifier,omitempty"`
	MPLSLabel        uint32                   `yaml:"mpls_label,omitempty"`
	SupportedBy      []FABRIDConnectionPoints `yaml:"connections,omitempty"`
}

// Validate validates that all values are parsable.
func (cfg *FABRIDPolicy) Validate() error {
	for _, connectionPoint := range cfg.SupportedBy {
		if err := config.ValidateAll(&connectionPoint); err != nil {
			return serrors.WrapStr("Validating supported interfaces failed", err)
		}
	}
	if cfg.IsLocalPolicy && (cfg.LocalIdentifier == 0 || cfg.LocalDescription == "") {
		return serrors.New("Local policy configuration must not be empty.")
	} else if !cfg.IsLocalPolicy && cfg.GlobalIdentifier == 0 {
		return serrors.New("Global policy identifier must be valid.")
	}

	return nil
}

// Sample writes a config sample to the writer.
func (cfg *FABRIDPolicy) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fabridLocalPolicySample)
}

type FABRIDConnectionPoints struct {
	Ingress FABRIDConnectionPoint `yaml:"ingress,omitempty"`
	Egress  FABRIDConnectionPoint `yaml:"egress,omitempty"`
}

// Validate validates that all values are parsable.
func (cfg *FABRIDConnectionPoints) Validate() error {
	return config.ValidateAll(&cfg.Ingress, &cfg.Egress)
}

type FABRIDConnectionPoint struct {
	Type      fabrid.ConnectionPointType `yaml:"type,omitempty"`
	IPAddress string                     `yaml:"ip,omitempty"`
	Prefix    uint8                      `yaml:"prefix,omitempty"`
	Interface uint16                     `yaml:"interface,omitempty"`
}

// Validate validates that all values are parsable.
func (cfg *FABRIDConnectionPoint) Validate() error {
	switch strings.ToLower(string(cfg.Type)) {
	case string(fabrid.Unspecified):
		cfg.Type = fabrid.Unspecified
	case string(fabrid.IPv4Range):
		cfg.Type = fabrid.IPv4Range
	case string(fabrid.IPv6Range):
		cfg.Type = fabrid.IPv6Range
	case string(fabrid.Interface):
		cfg.Type = fabrid.Interface
	default:
		return serrors.New("unknown FABRID connection point", "type", cfg.Type)
	}
	if cfg.Type == fabrid.Interface && cfg.Interface == 0 {
		return serrors.New("Invalid interface for connection point")
	} else if cfg.Type == fabrid.IPv6Range && (cfg.IPAddress == "" || cfg.Prefix > 128) {
		return serrors.New("Invalid IPv6 Address range for connection point")
	} else if cfg.Type == fabrid.IPv4Range && (cfg.IPAddress == "" || cfg.Prefix > 32) {
		return serrors.New("Invalid IPv4 Address range for connection point")
	}
	return nil
}
