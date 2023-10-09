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

package slayers_test

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/stretchr/testify/assert"
)

func TestFabridDecode(t *testing.T) {
	type test struct {
		name     string
		raw      []byte
		inf      *path.InfoField
		base     *scion.Base
		validate func(slayers.FabridOption, error, *testing.T)
	}
	unixNow := uint32(time.Now().Unix())
	tests := []test{
		{
			name: "Raw is nil",
			raw:  nil,
			validate: func(fo slayers.FabridOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Inf is nil",
			raw:  make([]byte, 100),
			inf:  nil,
			validate: func(fo slayers.FabridOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Base is nil",
			raw:  make([]byte, 100),
			inf:  &path.InfoField{},
			base: nil,
			validate: func(fo slayers.FabridOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Raw fabrid too short",
			raw:  make([]byte, 11),
			inf:  &path.InfoField{},
			base: &scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF: 1,
				},
				NumHops: 1,
			},
			validate: func(fo slayers.FabridOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Raw fabrid parses with 1 HF",
			raw:  make([]byte, 12),
			inf:  &path.InfoField{},
			base: &scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF: 1,
				},
				NumHops: 1,
			},
			validate: func(fo slayers.FabridOption, err error, t *testing.T) {
				assert.NoError(t, err)
			},
		},
		{
			name: "Raw fabrid parses with 2 HF",
			raw:  make([]byte, 16),
			inf:  &path.InfoField{},
			base: &scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF: 1,
				},
				NumHops: 2,
			},
			validate: func(fo slayers.FabridOption, err error, t *testing.T) {
				assert.NoError(t, err)
			},
		},
		{
			name: "Raw fabrid parses with 61 HF",
			raw:  make([]byte, 252),
			inf:  &path.InfoField{},
			base: &scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF: 1,
				},
				NumHops: 61,
			},
			validate: func(fo slayers.FabridOption, err error, t *testing.T) {
				assert.NoError(t, err)
			},
		},
		{
			name: "Raw fabrid fails parsing 62 HF",
			raw:  make([]byte, 1000),
			inf:  &path.InfoField{},
			base: &scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF: 1,
				},
				NumHops: 62,
			},
			validate: func(fo slayers.FabridOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Parses fabrid correctly",
			raw: []byte{
				0xff, 0x00, 0x00, 0x01,
				0x01, 0x02, 0x03, 0x04,
				0x66, 0x77, 0x88, 0x99,
				0xaa, 0xbb, 0xcc, 0xdd,
			},
			inf: &path.InfoField{
				Timestamp: unixNow,
			},
			base: &scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF: 1,
				},
				NumHops: 2,
			},
			validate: func(fo slayers.FabridOption, err error, t *testing.T) {
				assert.NoError(t, err)
				expectedTime := int64(unixNow)*1000 + 0x7000001
				assert.Equal(t, expectedTime, fo.PktTimestamp.UnixMilli())
				assert.Equal(t, uint32(0x01020304), fo.PacketID)
				assert.Equal(t, 2, len(fo.HopfieldMetadata))
				assert.Equal(t, uint8(0x66), fo.HopfieldMetadata[0].EncryptedPolicyID)
				assert.Equal(t, [3]byte{0x77, 0x88, 0x99}, fo.HopfieldMetadata[0].HopValidationField)
				assert.Equal(t, uint8(0xaa), fo.HopfieldMetadata[1].EncryptedPolicyID)
				assert.Equal(t, [3]byte{0xbb, 0xcc, 0xdd}, fo.HopfieldMetadata[1].HopValidationField)
			},
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				f := slayers.FabridOption{}
				err := f.DecodeFull(tc.raw, tc.inf, tc.base)
				tc.validate(f, err, t)
			})
		}(tc)
	}
}

func TestFabridSerialize(t *testing.T) {
	type test struct {
		name     string
		fabrid   *slayers.FabridOption
		buffer   []byte
		validate func([]byte, error, *testing.T)
	}
	unixNow := uint32(time.Now().Unix())

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
			fabrid: &slayers.FabridOption{
				HopfieldMetadata: make([]slayers.FabridHopfieldMetadata, 1),
				FirstInfoField:   &path.InfoField{},
			},
			buffer: make([]byte, 11),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Infofield is nil",
			fabrid: &slayers.FabridOption{
				HopfieldMetadata: make([]slayers.FabridHopfieldMetadata, 1),
			},
			buffer: make([]byte, 12),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Too many hops",
			fabrid: &slayers.FabridOption{
				HopfieldMetadata: make([]slayers.FabridHopfieldMetadata, 62),
				FirstInfoField: &path.InfoField{
					Timestamp: unixNow,
				},
			},
			buffer: make([]byte, 256),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Fabrid serializes correctly",
			fabrid: &slayers.FabridOption{
				HopfieldMetadata: []slayers.FabridHopfieldMetadata{
					{
						EncryptedPolicyID:  0x11,
						HopValidationField: [3]byte{0x22, 0x33, 0x44},
					},
					{
						EncryptedPolicyID:  0xaa,
						HopValidationField: [3]byte{0xbb, 0xcc, 0xdd},
					},
				},
				FirstInfoField: &path.InfoField{
					Timestamp: unixNow,
				},
				PacketID:     0xa1a2a3a4,
				PktTimestamp: time.Unix(int64(unixNow), int64(0x7000001*time.Millisecond)),
			},
			buffer: make([]byte, 16),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x07, 0x00, 0x00, 0x01}, b[0:4])   //time
				assert.Equal(t, []byte{0xa1, 0xa2, 0xa3, 0xa4}, b[4:8])   //pktID
				assert.Equal(t, []byte{0x11, 0x22, 0x33, 0x44}, b[8:12])  //HF1
				assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd}, b[12:16]) //HF2
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
