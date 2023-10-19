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

package extension_test

import (
	"testing"

	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/stretchr/testify/assert"
)

func TestFabridDecode(t *testing.T) {
	type test struct {
		name     string
		o        *slayers.HopByHopOption
		base     *scion.Base
		validate func(extension.FabridOption, error, *testing.T)
	}
	tests := []test{
		{
			name: "Base is nil",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeFabrid,
				OptData: make([]byte, 100),
			},
			base: nil,
			validate: func(fo extension.FabridOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "wrong option type",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeIdentifier,
				OptData: make([]byte, 8),
			},
			base: &scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF: 1,
				},
				NumHops: 1,
			},
			validate: func(fo extension.FabridOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Raw fabrid too short",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeFabrid,
				OptData: make([]byte, 7),
			},
			base: &scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF: 1,
				},
				NumHops: 1,
			},
			validate: func(fo extension.FabridOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Raw fabrid parses with 62 HF",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeFabrid,
				OptData: make([]byte, 252),
			},
			base: &scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF: 1,
				},
				NumHops: extension.MaxSupportedFabridHops,
			},
			validate: func(fo extension.FabridOption, err error, t *testing.T) {
				assert.NoError(t, err)
			},
		},
		{
			name: "Raw fabrid fails parsing 63 HF",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeFabrid,
				OptData: make([]byte, 1000),
			},
			base: &scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF: 1,
				},
				NumHops: extension.MaxSupportedFabridHops + 1,
			},
			validate: func(fo extension.FabridOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Parses fabrid correctly",
			o: &slayers.HopByHopOption{
				OptType: slayers.OptTypeFabrid,
				OptData: []byte{
					0x66, 0x77, 0x88, 0x99,
					0xaa, 0xbb, 0xcc, 0xdd,
					0x22, 0x33, 0x44, 0x55,
				},
			},
			base: &scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF: 1,
				},
				NumHops: 2,
			},
			validate: func(fo extension.FabridOption, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(fo.HopfieldMetadata))
				assert.Equal(t, uint8(0x66), fo.HopfieldMetadata[0].EncryptedPolicyID)
				assert.Equal(t, [3]byte{0x77, 0x88, 0x99}, fo.HopfieldMetadata[0].HopValidationField)
				assert.Equal(t, uint8(0xaa), fo.HopfieldMetadata[1].EncryptedPolicyID)
				assert.Equal(t, [3]byte{0xbb, 0xcc, 0xdd}, fo.HopfieldMetadata[1].HopValidationField)
				assert.Equal(t, [4]byte{0x22, 0x33, 0x44, 0x55}, fo.PathValidator)
			},
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				f, err := extension.ParseFabridOptionFullExtension(tc.o, tc.base)
				tc.validate(f, err, t)
			})
		}(tc)
	}
}

func TestFabridSerialize(t *testing.T) {
	type test struct {
		name     string
		fabrid   *extension.FabridOption
		buffer   []byte
		validate func([]byte, error, *testing.T)
	}

	tests := []test{
		{
			name:   "Fabrid option is nil",
			fabrid: nil,
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Buffer too small",
			fabrid: &extension.FabridOption{
				HopfieldMetadata: make([]extension.FabridHopfieldMetadata, 1),
			},
			buffer: make([]byte, 7),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Too many hops",
			fabrid: &extension.FabridOption{
				HopfieldMetadata: make([]extension.FabridHopfieldMetadata, extension.MaxSupportedFabridHops+1),
			},
			buffer: make([]byte, 256),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Fabrid serializes correctly",
			fabrid: &extension.FabridOption{
				HopfieldMetadata: []extension.FabridHopfieldMetadata{
					{
						EncryptedPolicyID:  0x11,
						HopValidationField: [3]byte{0x22, 0x33, 0x44},
					},
					{
						EncryptedPolicyID:  0xaa,
						HopValidationField: [3]byte{0xbb, 0xcc, 0xdd},
					},
				},
				PathValidator: [4]byte{0x11, 0x22, 0x33, 0x44},
			},
			buffer: make([]byte, 12),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x11, 0x22, 0x33, 0x44}, b[0:4])  //HF1
				assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd}, b[4:8])  //HF2
				assert.Equal(t, []byte{0x11, 0x22, 0x33, 0x44}, b[8:12]) //Path validator
			},
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := tc.fabrid.SerializeTo(tc.buffer)
				tc.validate(tc.buffer, err, t)
			})
		}(tc)
	}
}
