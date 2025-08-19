// Copyright 2025 ETH Zurich
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

package monitor_test

import (
	"crypto/sha256"
	"hash"
	"hash/fnv"
	"testing"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/experimental/pot/monitor"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
)

func generatePacket(numHops uint8, payloadSize uint16) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	s := &slayers.SCION{
		Version:      0,
		TrafficClass: 0,
		FlowID:       1,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        xtest.MustParseIA("1-ff00:0:110"),
		SrcIA:        xtest.MustParseIA("1-ff00:0:111"),
		Path:         &scion.Raw{},
		PayloadLen:   payloadSize,
	}
	scionpath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 0,
				SegLen: [3]uint8{numHops, 0, 0},
			},
			NumINF:  1,
			NumHops: int(numHops),
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(time.Now())},
		},

		HopFields: []path.HopField{},
	}
	for i := 0; i < int(numHops); i += 2 {
		scionpath.HopFields = append(scionpath.HopFields, path.HopField{
			ConsIngress: uint16(i), ConsEgress: uint16(i + 1), Mac: [6]byte{0, 1, 2, 3, 4, 5},
		})
	}
	s.Path = scionpath
	payload := make([]byte, payloadSize)
	for i := 0; i < int(payloadSize); i++ {
		payload[i] = byte(i)
	}
	err := gopacket.SerializeLayers(buffer,
		gopacket.SerializeOptions{FixLengths: true},
		s, gopacket.Payload(payload))
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func BenchmarkHash(b *testing.B) {
	// first generate a packet
	pkt, err := generatePacket(6, 130)
	assert.NoError(b, err)
	blake, _ := blake2b.New256(nil)
	hashFunctions := []struct {
		name   string
		hasher hash.Hash
	}{
		{"sha256", sha256.New()},
		{"blake2b 256bit", blake},
		{"fnv1a-128bit", fnv.New128a()},
		{"xxhash 64bit", xxhash.New()},
	}
	for _, h := range hashFunctions {
		b.Run(h.name, func(b *testing.B) {
			monitor := monitor.NewMonitor(nil, h.hasher)
			hashBuffer := make([]byte, h.hasher.Size())
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				monitor.HashPacket(pkt, hashBuffer)
			}
		})
	}
}
