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

	"github.com/scionproto/scion/pkg/experimental/pot/monitor"
	"github.com/stretchr/testify/assert"
)

func BenchmarkParser(b *testing.B) {
	payloadSizes := []int{130, 380, 880, 4880}
	for _, payloadSize := range payloadSizes {
		b.Run(fmt.Sprintf("Parsing_no_hbh_%d", payloadSize), func(b *testing.B) {
			pkt, _, err := generatePacket(6, uint16(payloadSize), false)
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
			pkt, _, err := generatePacket(6, uint16(payloadSize), true)
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

}
