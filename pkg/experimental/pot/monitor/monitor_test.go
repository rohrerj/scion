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
	"fmt"
	"hash"
	"hash/crc64"
	"testing"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/experimental/pot/monitor"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
)

func generatePacket(numHops uint8, payloadSize uint16, useHbhExtension bool) ([]byte, *slayers.SCION, error) {
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
	udp := &slayers.UDP{
		SrcPort: 1234,
		DstPort: 4321,
	}
	payload := make([]byte, payloadSize)
	for i := 0; i < int(payloadSize); i++ {
		payload[i] = byte(i)
	}
	if useHbhExtension {
		s.NextHdr = slayers.HopByHopClass
		identifier := extension.IdentifierOption{
			BaseTimestamp: scionpath.InfoFields[0].Timestamp,
			Timestamp:     time.Unix(0, int64(time.Millisecond)*int64(1785+1000*scionpath.InfoFields[0].Timestamp)),
			PacketID:      555}
		identifierData := make([]byte, 8)
		identifier.Serialize(identifierData)
		hbhExt := &slayers.HopByHopExtn{
			Options: []*slayers.HopByHopOption{
				{
					OptType:      slayers.OptTypeIdentifier,
					OptDataLen:   8,
					ActualLength: 8,
					OptData:      identifierData,
				},
			},
		}
		err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
			s, hbhExt, udp, gopacket.Payload(payload))
		if err != nil {
			return nil, nil, err
		}
	} else {
		err := gopacket.SerializeLayers(buffer,
			gopacket.SerializeOptions{FixLengths: true},
			s, gopacket.Payload(payload))
		if err != nil {
			return nil, nil, err
		}
	}

	return buffer.Bytes(), s, nil
}

func BenchmarkHash(b *testing.B) {
	// first generate a packet
	blake, _ := blake2b.New256(nil)

	hashFunctions := []struct {
		name   string
		hasher hash.Hash
	}{
		{"sha256", sha256.New()},
		{"blake2b 256bit", blake},
		{"xxhash 64bit", xxhash.New()},
		{"crc 64bit", crc64.New(crc64.MakeTable(crc64.ISO))},
	}
	payloadSizes := []int{130, 380, 880, 4880}
	sampler := &monitor.StrideSampler{}
	for _, payloadSize := range payloadSizes {
		for _, h := range hashFunctions {
			b.Run(fmt.Sprintf("%s_no_hbh_%d", h.name, payloadSize), func(b *testing.B) {
				pkt, _, err := generatePacket(6, uint16(payloadSize), false)
				assert.NoError(b, err)
				monitor := monitor.NewMonitor(nil, h.hasher, sampler)
				hashBuffer := make([]byte, h.hasher.Size())
				pktCopy := make([]byte, len(pkt))
				copy(pktCopy, pkt)
				err = monitor.HashPacket(pkt, hashBuffer)
				assert.NoError(b, err)
				assert.Equal(b, pkt, pktCopy)

				assert.NoError(b, err)
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					err := monitor.HashPacket(pkt, hashBuffer)
					assert.NoError(b, err)
				}
			})
			b.Run(fmt.Sprintf("%s_with_hbh_%d", h.name, payloadSize), func(b *testing.B) {
				pkt, _, err := generatePacket(6, uint16(payloadSize), true)
				assert.NoError(b, err)
				monitor := monitor.NewMonitor(nil, h.hasher, sampler)
				hashBuffer := make([]byte, h.hasher.Size())
				pktCopy := make([]byte, len(pkt))
				copy(pktCopy, pkt)
				err = monitor.HashPacket(pkt, hashBuffer)
				assert.NoError(b, err)
				assert.Equal(b, pkt, pktCopy)

				assert.NoError(b, err)
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					err := monitor.HashPacket(pkt, hashBuffer)
					assert.NoError(b, err)
				}
			})
		}
	}
}

func TestHashing(t *testing.T) {
	//monitor := monitor.NewMonitor(nil, sha256.New(), &monitor.StrideSampler{})

}
