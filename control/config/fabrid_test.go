package config_test

import (
	"bytes"
	"fmt"
	"github.com/scionproto/scion/control/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
	"testing"
)

func TestFabridSample(t *testing.T) {
	var sample bytes.Buffer
	pol := &config.FABRIDPolicy{}
	pol.Sample(&sample, nil, nil)
	err := yaml.UnmarshalStrict(sample.Bytes(), pol)
	fmt.Println(sample.String())
	assert.NoError(t, err)
	err = pol.Validate()
	assert.NoError(t, err)
}

func TestFabridPolicyValidation(t *testing.T) {
	tests := map[string]struct {
		Policy string
		assert assert.ErrorAssertionFunc
	}{
		"valid": {
			Policy: `connections:
    - ingress:
        type: interface
        interface: 1
      egress:
        type: ipv4
        ip: 192.168.2.1
        prefix: 24
local: true
local_identifier: 55
local_description: Fabrid Example Policy`,
			assert: assert.NoError,
		},
		"invalid interface": {
			Policy: `connections:
    - ingress:
        type: interface
        interface: 0
      egress:
        type: ipv4
        ip: 192.168.2.1
        prefix: 24
local: true
local_identifier: 55
local_description: Fabrid Example Policy`,
			assert: assert.Error,
		},
		"invalid prefix ipv4": {
			Policy: `connections:
    - ingress:
        type: interface
        interface: 1
      egress:
        type: ipv4
        ip: 192.168.2.1
        prefix: 33
local: true
local_identifier: 55
local_description: Fabrid Example Policy`,
			assert: assert.Error,
		},
		"valid prefix ipv6": {
			Policy: `connections:
    - ingress:
        type: interface
        interface: 1
      egress:
        type: ipv6
        ip: 2001::1a2b
        prefix: 33
local: true
local_identifier: 55
local_description: Fabrid Example Policy`,
			assert: assert.NoError,
		},
		"invalid prefix ipv6": {
			Policy: `connections:
    - ingress:
        type: interface
        interface: 1
      egress:
        type: ipv6
        ip: 2001::1a2b
        prefix: 129
local: true
local_identifier: 55
local_description: Fabrid Example Policy`,
			assert: assert.Error,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pol := &config.FABRIDPolicy{}
			err := yaml.UnmarshalStrict([]byte(tc.Policy), pol)
			require.NoError(t, err)
			err = pol.Validate()
			tc.assert(t, err)
		})
	}
}
