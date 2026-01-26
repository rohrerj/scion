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
	"fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/experimental/pot/monitor"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/stretchr/testify/assert"
)

func BenchmarkParser(b *testing.B) {
	payloadSizes := []int{130, 380, 880, 4880}
	for _, payloadSize := range payloadSizes {
		b.Run(fmt.Sprintf("Parsing_no_hbh_%d", payloadSize), func(b *testing.B) {
			pkt, _, err := generatePacket([3]uint8{6, 0, 0}, uint16(payloadSize), false)
			assert.NoError(b, err)
			parser := monitor.Parser{}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := parser.Parse(pkt)
				assert.NoError(b, err)
				parser.UndoZero(pkt)
			}
		})
		b.Run(fmt.Sprintf("Parsing_with_hbh_%d", payloadSize), func(b *testing.B) {
			pkt, _, err := generatePacket([3]uint8{6, 0, 0}, uint16(payloadSize), true)
			assert.NoError(b, err)
			parser := monitor.Parser{}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := parser.Parse(pkt)
				assert.NoError(b, err)
				parser.UndoZero(pkt)
			}
		})
	}
}

func TestParser(t *testing.T) {
	pkt, s, err := generatePacket([3]uint8{6, 2, 2}, uint16(120), false)
	pktCopy := make([]byte, len(pkt))
	copy(pktCopy, pkt)
	assert.NoError(t, err)
	parser := monitor.Parser{}
	err = parser.Parse(pkt)
	assert.NoError(t, err)
	parser.UndoZero(pkt)
	hCopy := [2]monitor.HashRegion{}

	copy(hCopy[:], parser.HashRegions[:])
	t.Log(parser.HashRegions)
	t.Log(hCopy)
	d := s.Path.(*scion.Decoded)
	buf := gopacket.NewSerializeBuffer()
	for i := 0; i < 9; i++ {
		err = d.IncPath()
		s.SerializeTo(buf, gopacket.SerializeOptions{})
		assert.NoError(t, err)
		copy(pkt, buf.Bytes())
		parser = monitor.Parser{}
		err = parser.Parse(pkt)
		assert.NoError(t, err)
		parser.UndoZero(pkt)
		assert.Equal(t, hCopy, parser.HashRegions)
	}
}
