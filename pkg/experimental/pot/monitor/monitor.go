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

package monitor

import (
	"encoding/binary"
	"hash"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
)

type Bucket struct {
	Data    []byte
	Counter uint32
}

type Monitor struct {
	workers    []*MonitorWorker
	mtx        sync.Mutex
	NewHasher  func() hash.Hash
	NewSampler func() Sampler
}

type MonitorWorker struct {
	hasher          hash.Hash
	Parser          Parser
	hashSampleSlice [64]byte
	Sampler         Sampler
	Buckets         [Num_windows]map[uint64]Bucket
	HashBuffer      []byte
}

func (monitor *Monitor) NewMonitorWorker() *MonitorWorker {
	monitor.mtx.Lock()
	defer monitor.mtx.Unlock()
	hasher := monitor.NewHasher()
	m := &MonitorWorker{
		hasher:     hasher,
		Parser:     Parser{},
		Sampler:    monitor.NewSampler(),
		Buckets:    [Num_windows]map[uint64]Bucket{},
		HashBuffer: make([]byte, hasher.Size()),
	}
	monitor.workers = append(monitor.workers, m)
	for i := 0; i < Num_windows; i++ {
		m.Buckets[i] = make(map[uint64]Bucket)
	}
	return m
}

func (m *MonitorWorker) ProcessPacket(packet []byte, ingress uint16, egress uint16, no_error bool) error {
	firstLine := binary.BigEndian.Uint32(packet[:4])
	flowID := firstLine & 0xFFFFF
	time_window := ComputeTimeWindowIndex(int(flowID), time.Now())
	log.Debug("Monitor process", "window", time_window)
	err := m.HashPacket(packet)
	if err != nil {
		return err
	}
	return m.StoreValueInBucket(m.HashBuffer, ingress, egress, time_window, no_error)
}

func (m *MonitorWorker) ClearBuckets(time_window int) {
	clear(m.Buckets[time_window])
}

func (m *MonitorWorker) StoreValueInBucket(value []byte, ingress uint16, egress uint16, time_window int, no_error bool) error {
	if int(time_window) > Num_windows {
		return serrors.New("time_window index out of bounds")
	}
	var index uint64
	if no_error {
		index = uint64(ingress)<<16 + uint64(egress)
	} else {
		//in the error case we don't consider the egress because it might not be known
		//but the ingress is always known
		index = uint64(ingress)<<16 + uint64(1)<<32
	}

	item, found := m.Buckets[time_window][index]
	if !found {
		// bucket does not exist, create new bucket
		new_bucket := Bucket{
			Data:    make([]byte, len(value)),
			Counter: 1,
		}
		copy(new_bucket.Data, value)
		m.Buckets[time_window][index] = new_bucket
	} else {
		m.Aggregate(&item, value, 1)
	}
	return nil
}

// Aggregate aggregates newValue to the bucket and increases the counter inside the bucket by counter
func (m *MonitorWorker) Aggregate(bucket *Bucket, newValue []byte, counter uint32) error {
	if len(bucket.Data) != len(newValue) {
		return serrors.New("slices need equal length")
	}
	for i := 0; i < len(bucket.Data); i++ {
		bucket.Data[i] ^= newValue[i]
	}
	bucket.Counter += counter
	return nil
}

func WindowIndex(t time.Time) int {
	cycle := Window_length * time.Duration(Num_windows)
	d := time.Duration(t.UnixNano())
	offset := d % cycle
	return int(offset / Window_length)
}

func GetWindowIndexForTime(send_time time.Time) int {
	return int(WindowIndex(send_time) % Num_Windows_Per_Frame)
}

/*
Maximum clock skew for fixed window length and number of bits:
L=0.001s, N=10 -> 0.5s
L=0.001s, N=11 -> 1s
L=0.001s, N=12 -> 2s
L=0.01s,  N=7  -> 0.63s
L=0.01s,  N=8  -> 1.27s
L=0.1s,   N=4  -> 0.75s
L=0.1s,   N=5  -> 1.5s
L=0.1s,   N=6  -> 3.1s
L=0.5s,   N=2  -> 0.75s
L=0.5s,   N=3  -> 1.5s
L=0.5s,   N=4  -> 3.0s
L=1.0s,   N=1  -> 0.5s
L=1.0s,   N=2  -> 1.5s
L=1.0s,   N=3  -> 3.5s
L=1.0s,   N=4  -> 7.5s
L=1.0s,   N=5  -> 15.5s
L=2.0s,   N=1  -> 1.0s
L=2.0s,   N=2  -> 3.0s
L=2.0s,   N=3  -> 7.0s
*/

// const Frame_length = 2 * time.Second
const Window_length = 1 * time.Millisecond
const Num_Bits = 12
const Num_Frames = 4
const Num_windows = Num_Windows_Per_Frame * Num_Frames
const Num_Windows_Per_Frame = 1 << Num_Bits

func ComputeTimeWindowIndex(window_index int, arrival_time time.Time) int {
	const mask = (1 << Num_Bits) - 1
	baseIndex := WindowIndex(arrival_time)
	targetIndex := window_index & mask
	if baseIndex%Num_Windows_Per_Frame == targetIndex {
		// the target index matches the computed base index
		return baseIndex
	}
	// distance to the left
	distance1 := (baseIndex - targetIndex + Num_windows) % Num_Windows_Per_Frame
	// distance to the right
	distance2 := (-baseIndex + targetIndex + Num_windows) % Num_Windows_Per_Frame
	if distance1 < distance2 {
		return (baseIndex - distance1 + Num_windows) % Num_windows
	} else if distance2 < distance1 {
		return (baseIndex + distance2) % Num_windows
	} else {
		if (time.Duration(arrival_time.UnixNano()) % Window_length) < Window_length/2 {
			// arrival_time lies in first half of time_window
			return (baseIndex - distance1 + Num_windows) % Num_windows
		} else {
			// arrival_time lies in second half of time_window
			return (baseIndex + distance1) % Num_windows
		}
	}
}

func (m *MonitorWorker) HashAllPacket(packet []byte) error {
	m.hasher.Reset()
	err := m.Parser.Parse(packet)
	if err != nil {
		return err
	}
	_, err = m.hasher.Write(m.Parser.HashRegions[0])
	if err != nil {
		return err
	}
	_, err = m.hasher.Write(m.Parser.HashRegions[1])
	if err != nil {
		return err
	}
	m.hasher.Sum(m.HashBuffer[:0])
	m.Parser.UndoZero(packet)
	return nil
}

func (m *MonitorWorker) HashPacket(packet []byte) error {
	m.hasher.Reset()
	err := m.Parser.Parse(packet)
	if err != nil {
		return err
	}
	_, err = m.hasher.Write(m.Parser.HashRegions[0])
	if err != nil {
		return err
	}
	n := len(m.Parser.HashRegions[1])
	if m.Sampler == nil || n <= len(m.hashSampleSlice) {
		_, err = m.hasher.Write(m.Parser.HashRegions[1])
		if err != nil {
			return err
		}
	} else {
		m.Sampler.Sample(m.Parser.HashRegions[1], m.hashSampleSlice[:])
		_, err = m.hasher.Write(m.hashSampleSlice[:])
		if err != nil {
			return err
		}
	}
	m.hasher.Sum(m.HashBuffer[:0])
	m.Parser.UndoZero(packet)
	return nil
}
