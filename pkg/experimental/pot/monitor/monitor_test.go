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
	for _, payloadSize := range payloadSizes {
		for _, h := range hashFunctions {
			b.Run(fmt.Sprintf("%s_no_hbh_%d", h.name, payloadSize), func(b *testing.B) {
				pkt, _, err := generatePacket(6, uint16(payloadSize), false)
				assert.NoError(b, err)
				monitor := monitor.Monitor{
					NewHasher:  sha256.New,
					NewSampler: func() monitor.Sampler { return &monitor.StrideSampler{} },
				}
				monitorWorker := monitor.NewMonitorWorker()
				pktCopy := make([]byte, len(pkt))
				copy(pktCopy, pkt)
				err = monitorWorker.HashPacket(pkt)
				assert.NoError(b, err)
				assert.Equal(b, pkt, pktCopy)

				assert.NoError(b, err)
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					err := monitorWorker.HashPacket(pkt)
					assert.NoError(b, err)
				}
			})
			b.Run(fmt.Sprintf("%s_with_hbh_%d", h.name, payloadSize), func(b *testing.B) {
				pkt, _, err := generatePacket(6, uint16(payloadSize), true)
				assert.NoError(b, err)
				monitor := monitor.Monitor{
					NewHasher:  sha256.New,
					NewSampler: func() monitor.Sampler { return &monitor.StrideSampler{} },
				}
				monitorWorker := monitor.NewMonitorWorker()
				pktCopy := make([]byte, len(pkt))
				copy(pktCopy, pkt)
				err = monitorWorker.HashPacket(pkt)
				assert.NoError(b, err)
				assert.Equal(b, pkt, pktCopy)

				assert.NoError(b, err)
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					err := monitorWorker.HashPacket(pkt)
					assert.NoError(b, err)
				}
			})
		}
	}
}

func TestComputeTimeWindow(t *testing.T) {
	type Test struct {
		name           string
		flowID         uint8
		arrival_time   time.Time
		expected_index uint8
	}
	tests := []Test{
		{
			name:           "window_even_first_half",
			flowID:         0,
			arrival_time:   time.Unix(int64(monitor.Window_length.Seconds()), 0),
			expected_index: 1,
		},
		{
			name:           "window_even_second_half",
			flowID:         0,
			arrival_time:   time.Unix(int64(monitor.Window_length.Seconds()), -1),
			expected_index: 1,
		},
		{
			name:           "window_odd_first_half",
			flowID:         1,
			arrival_time:   time.Unix(int64(monitor.Window_length.Seconds()), 0),
			expected_index: 1,
		},
		{
			name:           "window_odd_second_half",
			flowID:         1,
			arrival_time:   time.Unix(int64(monitor.Window_length.Seconds()), -1),
			expected_index: 0,
		},
		{
			name:           "window_even_first_half_2T",
			flowID:         0,
			arrival_time:   time.Unix(int64(monitor.Window_length.Seconds()*2), 15),
			expected_index: 2,
		},
		{
			name:           "window_even_first_half_3T",
			flowID:         0,
			arrival_time:   time.Unix(int64(monitor.Window_length.Seconds()*3), 15),
			expected_index: 3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected_index, monitor.ComputeTimeWindowIndex(int(test.flowID), test.arrival_time))
		})
	}
}

// This test tests that as long as latency and clock screw are within
// a certain bound, the same time window is chosen.
// If the base time is close the middle, the odd bit should be chosen
// and if the base time is closer to the edge of the time window, take the even bit
func TestComputeTimeWindowDifferentTime(t *testing.T) {
	type Entry struct {
		Latency_and_clock_screw time.Duration
	}
	type Test struct {
		name    string
		flowid  int
		t_base  time.Time
		entries []Entry
	}
	tests := []Test{
		{
			name:   "odd_middle",
			flowid: 1,
			t_base: time.Unix(int64(monitor.Window_length.Seconds()+monitor.Window_length.Seconds()/2), 0),
			entries: []Entry{
				{
					Latency_and_clock_screw: -1000 * time.Millisecond,
				},
				{
					Latency_and_clock_screw: 999 * time.Millisecond,
				},
			},
		},
		{
			name:   "even_begin",
			flowid: 0,
			t_base: time.Unix(int64(monitor.Window_length.Seconds()), 0),
			entries: []Entry{
				{
					Latency_and_clock_screw: -1000 * time.Millisecond,
				},
				{
					Latency_and_clock_screw: 999 * time.Millisecond,
				},
			},
		},
		{
			name:   "even_end",
			flowid: 0,
			t_base: time.Unix(int64(monitor.Window_length.Seconds()*2), -1),
			entries: []Entry{
				{
					Latency_and_clock_screw: -999 * time.Millisecond,
				},
				{
					Latency_and_clock_screw: 1000 * time.Millisecond,
				},
			},
		},
		{
			name:   "even_middle",
			flowid: 0,
			t_base: time.Unix(int64(monitor.Window_length.Seconds()+monitor.Window_length.Seconds()/2), 0),
			entries: []Entry{
				{
					Latency_and_clock_screw: 0 * time.Millisecond,
				},
				{
					Latency_and_clock_screw: 999 * time.Millisecond,
				},
			},
		},
		{
			name:   "odd_begin",
			flowid: 1,
			t_base: time.Unix(int64(monitor.Window_length.Seconds()), 0),
			entries: []Entry{
				{
					Latency_and_clock_screw: 0 * time.Millisecond,
				},
				{
					Latency_and_clock_screw: 999 * time.Millisecond,
				},
			},
		},
		{
			name:   "odd_end",
			flowid: 1,
			t_base: time.Unix(int64(monitor.Window_length.Seconds()*2), -1),
			entries: []Entry{
				{
					Latency_and_clock_screw: -999 * time.Millisecond,
				},
				{
					Latency_and_clock_screw: 0 * time.Millisecond,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			index_base := monitor.ComputeTimeWindowIndex(test.flowid, test.t_base)
			for _, entry := range test.entries {
				current_time := test.t_base.Add(entry.Latency_and_clock_screw)
				current_index := monitor.ComputeTimeWindowIndex(test.flowid, current_time)
				assert.Equal(t, index_base, current_index)
			}
		})
	}
}

func TestMonitor(t *testing.T) {
	monitor := monitor.Monitor{
		NewHasher:  sha256.New,
		NewSampler: func() monitor.Sampler { return &monitor.FirstAndLastSampler{} },
	}
	pkt1, _, err := generatePacket(6, uint16(250), false)
	assert.NoError(t, err)
	pkt2, _, err := generatePacket(6, uint16(350), false)
	assert.NoError(t, err)
	pkt3, _, err := generatePacket(6, uint16(450), false)
	assert.NoError(t, err)
	w1 := monitor.NewMonitorWorker()
	w2 := monitor.NewMonitorWorker()
	err = w1.ProcessPacket(pkt1, 1, 2)
	assert.NoError(t, err)
	err = w1.ProcessPacket(pkt2, 1, 2)
	assert.NoError(t, err)
	err = w2.ProcessPacket(pkt3, 1, 2)
	assert.NoError(t, err)
	//unit test work in progress
}
