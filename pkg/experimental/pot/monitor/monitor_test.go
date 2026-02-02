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
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc64"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/addr"
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

func generatePacket(segLen [3]uint8, payloadSize uint16, useHbhExtension bool) ([]byte, *slayers.SCION, error) {
	buffer := gopacket.NewSerializeBuffer()
	s := &slayers.SCION{
		Version:      0,
		TrafficClass: 0,
		FlowID:       1,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        xtest.MustParseIA("1-ff00:0:110"),
		SrcIA:        xtest.MustParseIA("1-ff00:0:111"),
		DstAddrType:  slayers.T4Ip,
		SrcAddrType:  slayers.T4Ip,
		RawDstAddr:   []byte{1, 1, 1, 1},
		RawSrcAddr:   []byte{2, 2, 2, 2},
		Path:         &scion.Raw{},
		PayloadLen:   payloadSize,
	}
	numInfs := 1
	numHops := segLen[0]
	if segLen[1] > 0 {
		numInfs++
		numHops += segLen[1]
	}
	if segLen[2] > 0 {
		numInfs++
		numHops += segLen[2]
	}
	scionpath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 0,
				SegLen: segLen,
			},
			NumINF:  numInfs,
			NumHops: int(numHops),
		},
		InfoFields: []path.InfoField{},
		HopFields:  []path.HopField{},
	}
	for i := 0; i < numInfs; i++ {
		scionpath.InfoFields = append(scionpath.InfoFields, path.InfoField{
			SegID: 0x111 + uint16(i), ConsDir: true, Timestamp: util.TimeToSecs(time.Now().Add(-time.Duration(i) * time.Minute)),
		})
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

func BenchmarkMonitor(b *testing.B) {
	// now we benchmark the monitor with fixed parameters
	// hasher = sha256, sampler = firstAndLastSampler, no hbh
	runtime.GOMAXPROCS(1)
	payloadSizes := []int{100, 500, 1000, 5000}
	segments := [][3]uint8{
		{6, 0, 0},
		{4, 2, 0},
		{2, 2, 2},
	}
	m := monitor.Monitor{
		NewHasher:  sha256.New,
		NewSampler: func() monitor.Sampler { return &monitor.FirstAndLastSampler{} },
	}
	sourceIA := xtest.MustParseIA("1-ff00:0:111")
	for segIndex, segment := range segments {
		for _, payloadSize := range payloadSizes {
			b.Run(fmt.Sprintf("Monitoring_%d_num_infs_%d", payloadSize, 1+segIndex), func(b *testing.B) {
				pkt, _, err := generatePacket(segment, uint16(payloadSize), false)
				assert.NoError(b, err)
				monitorWorker := m.NewMonitorWorker()
				for i := 0; i < b.N; i++ {
					monitorWorker.ProcessPacket(pkt, 1, 2, sourceIA)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					monitorWorker.ProcessPacket(pkt, 1, 2, sourceIA)
				}
			})
		}
	}
}

func BenchmarkMonitorBatches(b *testing.B) {
	// now we benchmark the monitor with fixed parameters
	// hasher = sha256, sampler = firstAndLastSampler, no hbh
	saveSamples := func(filename string, samples []int64) {
		f, err := os.Create(filename)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		w := bufio.NewWriter(f)
		for _, s := range samples {
			w.WriteString(strconv.FormatInt(s, 10))
			w.WriteByte('\n')
		}
		w.Flush()
	}
	runtime.GOMAXPROCS(1)
	segments := [][3]uint8{
		{3, 0, 0},
		{2, 1, 0},
		{1, 1, 1},

		{4, 0, 0},
		{3, 1, 0},
		{2, 1, 1},

		{5, 0, 0},
		{4, 1, 0},
		{3, 1, 1},

		{6, 0, 0},
		{5, 1, 0},
		{4, 1, 1},

		{7, 0, 0},
		{6, 1, 0},
		{5, 1, 1},

		{8, 0, 0},
		{7, 1, 0},
		{6, 1, 1},

		{9, 0, 0},
		{8, 1, 0},
		{7, 1, 1},

		{10, 0, 0},
		{9, 1, 0},
		{8, 1, 1},
	}
	m := monitor.Monitor{
		NewHasher:  sha256.New,
		NewSampler: func() monitor.Sampler { return &monitor.FirstAndLastSampler{} },
	}
	sourceIA := xtest.MustParseIA("1-ff00:0:111")
	for _, segment := range segments {
		numHops := segment[0] + segment[1] + segment[2]
		numInfs := 1
		if segment[1] != 0 {
			numInfs = 2
		}
		if segment[2] != 0 {
			numInfs = 3
		}
		//for _, payloadSize := range payloadSizes {
		b.Run(fmt.Sprintf("Monitoring_%d_hops_over_%d_infs", numHops, numInfs), func(b *testing.B) {
			pkt, _, err := generatePacket(segment, uint16(128), false)
			assert.NoError(b, err)
			monitorWorker := m.NewMonitorWorker()
			const batchSize = 4096
			samples := make([]int64, 0, b.N/batchSize)
			for j := 0; j < batchSize; j++ {
				monitorWorker.ProcessPacket(pkt, 1, 2, sourceIA)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i += batchSize {
				start := time.Now()
				for j := 0; j < batchSize; j++ {
					monitorWorker.ProcessPacket(pkt, 1, 2, sourceIA)
				}
				elapsed := time.Since(start).Nanoseconds()
				samples = append(samples, elapsed/int64(batchSize))
			}
			b.StopTimer()
			saveSamples(fmt.Sprintf("%s.txt", strings.Split(b.Name(), "/")[1]), samples)
		})
		//}
	}
}

func BenchmarkAggregate(b *testing.B) {
	payloadSizes := []int{100, 500, 1000, 5000}
	for _, payloadSize := range payloadSizes {
		pkt, _, err := generatePacket([3]uint8{6, 2, 2}, uint16(payloadSize), false)
		assert.NoError(b, err)
		m := monitor.Monitor{
			NewHasher:  sha256.New,
			NewSampler: func() monitor.Sampler { return &monitor.StrideSampler{} },
		}
		monitorWorker := m.NewMonitorWorker()
		monitorWorker.HashBuffer = make([]byte, 32)
		for i := 0; i < 32; i++ {
			monitorWorker.HashBuffer[i] = byte(i)
		}
		sourceIA := addr.MustIAFrom(1, 2)
		b.Run(fmt.Sprintf("aggregate_%d", payloadSize), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				firstLine := binary.BigEndian.Uint32(pkt[:4])
				flowID := firstLine & 0xFFFFF
				time_window := monitor.ComputeTimeWindowIndex(int(flowID), time.Now())
				/*err := m.HashPacket(packet) //we dont measure packet hashing so this is excluded
				if err != nil {
					return err
				}*/
				monitorWorker.StoreValueInBucket(monitorWorker.HashBuffer, 1, 2, time_window, sourceIA)
			}
		})
	}
}

func BenchmarkOnlyHash(b *testing.B) {
	//blake, _ := blake2b.New256(nil)

	hashFunctions := []struct {
		name   string
		hasher func() hash.Hash
	}{
		{"sha256", sha256.New},
		/*{"blake2b 256bit", func() hash.Hash { return blake }},
		{"xxhash 64bit", func() hash.Hash { return xxhash.New() }},
		{"crc 64bit", func() hash.Hash { return crc64.New(crc64.MakeTable(crc64.ISO)) }},*/
	}
	//payloadSizes := []int{128, 256, 512, 1024, 2048, 4096}
	for payloadSize := 4; payloadSize <= 256; payloadSize += 4 {
		payload := make([]byte, payloadSize)
		for i := 0; i < int(payloadSize); i++ {
			payload[i] = byte(i)
		}
		for _, h := range hashFunctions {
			hasher := h.hasher()
			out := make([]byte, hasher.Size())
			b.Run(fmt.Sprintf("%s_%d", h.name, payloadSize), func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					hasher.Reset()
					_, err := hasher.Write(payload)
					assert.NoError(b, err)
					hasher.Sum(out)
				}
			})
		}
	}
}

func BenchmarkHash(b *testing.B) {
	// first generate a packet
	blake, _ := blake2b.New256(nil)

	hashFunctions := []struct {
		name   string
		hasher func() hash.Hash
	}{
		{"sha256", sha256.New},
		{"blake2b 256bit", func() hash.Hash { return blake }},
		{"xxhash 64bit", func() hash.Hash { return xxhash.New() }},
		{"crc 64bit", func() hash.Hash { return crc64.New(crc64.MakeTable(crc64.ISO)) }},
	}
	payloadSizes := []int{100, 500, 1000, 5000}
	for _, payloadSize := range payloadSizes {
		for _, h := range hashFunctions {
			b.Run(fmt.Sprintf("%s_no_hbh_%d", h.name, payloadSize), func(b *testing.B) {
				pkt, _, err := generatePacket([3]uint8{6, 0, 0}, uint16(payloadSize), false)
				assert.NoError(b, err)
				monitor := monitor.Monitor{
					NewHasher:  h.hasher,
					NewSampler: func() monitor.Sampler { return &monitor.StrideSampler{} },
				}
				monitorWorker := monitor.NewMonitorWorker()
				pktCopy := make([]byte, len(pkt))
				copy(pktCopy, pkt)
				err = monitorWorker.HashPacket(pkt)
				assert.NoError(b, err)
				assert.Equal(b, pkt, pktCopy)
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					err := monitorWorker.HashPacket(pkt)
					assert.NoError(b, err)
				}
			})
			b.Run(fmt.Sprintf("%s_with_hbh_%d", h.name, payloadSize), func(b *testing.B) {
				pkt, _, err := generatePacket([3]uint8{6, 0, 0}, uint16(payloadSize), true)
				assert.NoError(b, err)
				monitor := monitor.Monitor{
					NewHasher:  h.hasher,
					NewSampler: func() monitor.Sampler { return &monitor.StrideSampler{} },
				}
				monitorWorker := monitor.NewMonitorWorker()
				pktCopy := make([]byte, len(pkt))
				copy(pktCopy, pkt)
				err = monitorWorker.HashPacket(pkt)
				assert.NoError(b, err)
				assert.Equal(b, pkt, pktCopy)

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
		expected_index int
	}
	tests := []Test{
		{
			name:           "window_even_first_half",
			flowID:         0,
			arrival_time:   time.Unix(8+int64(monitor.Window_length.Seconds()), 0),
			expected_index: 0,
		},
		{
			name:           "T1",
			flowID:         0,
			arrival_time:   time.Unix(8+int64(monitor.Window_length.Seconds()*2), 0),
			expected_index: 0,
		},
		{
			name:           "T2",
			flowID:         0,
			arrival_time:   time.Unix(8-1+int64(monitor.Window_length.Seconds()*2), 0),
			expected_index: 0,
		},
		{
			name:           "T3",
			flowID:         0,
			arrival_time:   time.Unix(8-2+int64(monitor.Window_length.Seconds()*2), 0),
			expected_index: 0,
		},
		{
			name:           "T4",
			flowID:         0,
			arrival_time:   time.Unix(8-2+int64(monitor.Window_length.Seconds()*2), -1),
			expected_index: 0,
		},
		/*{
			name:           "window_even_second_half",
			flowID:         0,
			arrival_time:   time.Unix(int64(monitor.Window_length.Seconds()), -1),
			expected_index: 0,
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
			expected_index: 1,
		},
		{
			name:           "window_even_first_half_2T",
			flowID:         0,
			arrival_time:   time.Unix(int64(monitor.Window_length.Seconds()*2), 0),
			expected_index: 2,
		},*/
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected_index, monitor.ComputeTimeWindowIndex(int(test.flowID), test.arrival_time))
		})
	}
	t.Fail()
}

func TestComputeTimeWindowIndex(t *testing.T) {
	now := time.Now()
	for i := 0; i < 100; i++ {
		v := rand.Intn(10000)
		new_time := now.Add(time.Duration(v) * time.Millisecond)
		flowID := monitor.GetWindowIndexForTime(new_time)
		targetWindow := monitor.ComputeTimeWindowIndex(flowID, new_time)
		for i := -20; i < 20; i++ {
			current_time := new_time.Add(time.Duration(i * int(time.Millisecond*100)))
			current_index := monitor.ComputeTimeWindowIndex(flowID, current_time)
			assert.Equal(t, targetWindow, current_index)
		}
	}
}

func TestMonitor(t *testing.T) {
	monitor := monitor.Monitor{
		NewHasher:  sha256.New,
		NewSampler: func() monitor.Sampler { return &monitor.FirstAndLastSampler{} },
	}
	pkt1, _, err := generatePacket([3]uint8{6, 0, 0}, uint16(250), false)
	assert.NoError(t, err)
	pkt2, _, err := generatePacket([3]uint8{6, 0, 0}, uint16(350), false)
	assert.NoError(t, err)
	pkt3, _, err := generatePacket([3]uint8{6, 0, 0}, uint16(450), false)
	assert.NoError(t, err)
	w1 := monitor.NewMonitorWorker()
	w2 := monitor.NewMonitorWorker()
	err = w1.ProcessPacket(pkt1, 1, 2, addr.MustIAFrom(1, 1))
	assert.NoError(t, err)
	err = w1.ProcessPacket(pkt2, 1, 2, addr.MustIAFrom(1, 1))
	assert.NoError(t, err)
	err = w2.ProcessPacket(pkt3, 1, 2, addr.MustIAFrom(1, 1))
	assert.NoError(t, err)
	//unit test work in progress
}
