// Copyright 2023 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fabrid

import (
	"github.com/scionproto/scion/control/config"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/extensions/fabrid"
	"gopkg.in/yaml.v2"
	"os"
	"path/filepath"
	"time"
)

const MaxFabridPolicies = 255

// TODO(jvanbommel): Can probably combine this with PolicyIdentifier
type RemotePolicyIdentifier struct {
	ISDAS      uint64
	Identifier uint32
}

type RemotePolicyDescription struct {
	Description string
	Expires     time.Time
}

//type FabridManagerInterface interface {
//	Reload() error
//	Load() error
//	Active() bool
//	GetIndexIdentifierMap() *fabrid.IndexIdentifierMap
//	GetSupportedIndicesMap() *fabrid.SupportedIndicesMap
//	GetIdentifierDescriptionMap() *map[uint32]string
//	GetMPLSMap() *map[uint8]uint32
//	GetRemotePolicyCache() *map[RemotePolicyIdentifier]RemotePolicyDescription
//}

type FabridManager struct {
	autoIncrIndex            int
	PoliciesPath             string
	SupportedIndicesMap      fabrid.SupportedIndicesMap
	IndexIdentifierMap       fabrid.IndexIdentifierMap
	IdentifierDescriptionMap map[uint32]string
	MPLSMap                  MPLSMap
	RemotePolicyCache        map[RemotePolicyIdentifier]RemotePolicyDescription
}

func NewFabridManager(policyPath string) (*FabridManager, error) {
	fb := &FabridManager{
		PoliciesPath:             policyPath,
		SupportedIndicesMap:      map[fabrid.ConnectionPair][]uint8{},
		IndexIdentifierMap:       map[uint8]*fabrid.PolicyIdentifier{},
		IdentifierDescriptionMap: map[uint32]string{},
		MPLSMap:                  MPLSMap{},
		RemotePolicyCache:        map[RemotePolicyIdentifier]RemotePolicyDescription{},
		autoIncrIndex:            0,
	}
	return fb, fb.Load()
}

func (f *FabridManager) Reload() error {
	f.IndexIdentifierMap = make(map[uint8]*fabrid.PolicyIdentifier)
	f.SupportedIndicesMap = make(map[fabrid.ConnectionPair][]uint8)
	f.MPLSMap = MPLSMap{Data: map[uint32]uint32{}, CurrentHash: []byte{}}
	f.IdentifierDescriptionMap = make(map[uint32]string)
	f.autoIncrIndex = 0
	return f.Load()
}

func (f *FabridManager) Load() error {
	if err := filepath.Walk(f.PoliciesPath, f.parseAndAdd); err != nil {
		return serrors.WrapStr("Unable to read the fabrid policies in folder", err, "path", f.PoliciesPath)
	}
	f.MPLSMap.UpdateHash()
	return nil
}

func (f *FabridManager) Active() bool {
	return len(f.SupportedIndicesMap) > 0
}

func (f *FabridManager) parseAndAdd(path string, fi os.FileInfo, err error) error {
	if !fi.Mode().IsRegular() {
		return nil
	}

	if f.autoIncrIndex > MaxFabridPolicies {
		return serrors.New("Amount of FABRID policies exceeds limit.")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return serrors.WrapStr("Unable to read the fabrid policy in file", err, "path", path)
	}
	pol, err := parseFABRIDYAMLPolicy(b)
	if err != nil {
		return err
	}

	policyIdx := uint8(f.autoIncrIndex)
	f.autoIncrIndex++

	if pol.IsLocalPolicy {
		f.IndexIdentifierMap[policyIdx] = &fabrid.PolicyIdentifier{
			Type:       fabrid.LocalPolicy,
			Identifier: pol.LocalIdentifier,
		}
		f.IdentifierDescriptionMap[pol.LocalIdentifier] = pol.LocalDescription
	} else {
		f.IndexIdentifierMap[policyIdx] = &fabrid.PolicyIdentifier{
			Type:       fabrid.GlobalPolicy,
			Identifier: pol.GlobalIdentifier,
		}
	}

	for _, connection := range pol.SupportedBy {
		var eg, ig fabrid.ConnectionPoint
		if connection.Egress.Type == fabrid.Interface {
			eg = fabrid.ConnectionPoint{
				Type:        fabrid.Interface,
				InterfaceId: connection.Egress.Interface,
			}
		} else if connection.Egress.Type == fabrid.IPv4Range || connection.Egress.Type == fabrid.IPv6Range {
			eg = fabrid.ConnectionPointFromString(connection.Egress.IPAddress, uint32(connection.Egress.Prefix), connection.Egress.Type)
		}
		if connection.Ingress.Type == fabrid.Interface {
			ig = fabrid.ConnectionPoint{
				Type:        fabrid.Interface,
				InterfaceId: connection.Ingress.Interface,
			}
		} else if connection.Ingress.Type == fabrid.IPv4Range || connection.Ingress.Type == fabrid.IPv6Range {
			ig = fabrid.ConnectionPointFromString(connection.Ingress.IPAddress, uint32(connection.Ingress.Prefix), connection.Ingress.Type)
		}
		ie := fabrid.ConnectionPair{
			Ingress: ig,
			Egress:  eg,
		}
		f.SupportedIndicesMap[ie] = append(f.SupportedIndicesMap[ie], policyIdx)
	}

	if pol.MPLSLabel != 0 {
		f.MPLSMap.Data[uint32(policyIdx)] = pol.MPLSLabel
	}

	log.Debug("Loaded FABRID policy", "pol", pol)
	return nil
}

func parseFABRIDYAMLPolicy(b []byte) (*config.FABRIDPolicy, error) {
	p := &config.FABRIDPolicy{}
	if err := yaml.UnmarshalStrict(b, p); err != nil {
		return nil, serrors.WrapStr("Unable to parse policy", err)
	}
	return p, nil
}
