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
	"hash"
	"sync"

	"github.com/scionproto/scion/pkg/private/serrors"
)

type Bucket []byte

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
	Buckets         [4]map[uint32]Bucket
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
		Buckets:    [4]map[uint32]Bucket{},
		HashBuffer: make([]byte, hasher.Size()),
	}
	monitor.workers = append(monitor.workers, m)
	for i := 0; i < len(m.Buckets); i++ {
		m.Buckets[i] = make(map[uint32]Bucket)
	}
	return m
}

func (m *MonitorWorker) ProcessPacket(packet []byte, ingress uint16, egress uint16) error {
	time_window := packet[3] & 0x3
	err := m.HashPacket(packet)
	if err != nil {
		return err
	}
	return m.StoreValueInBucket(m.HashBuffer, ingress, egress, time_window)
}

func (m *MonitorWorker) StoreValueInBucket(value []byte, ingress uint16, egress uint16, time_window uint8) error {
	if int(time_window) > len(m.Buckets) {
		return serrors.New("time_window index out of bounds")
	}
	index := uint32(ingress)<<16 + uint32(egress)
	item, found := m.Buckets[time_window][index]
	if !found {
		// bucket does not exist, create new bucket
		new_bucket := make(Bucket, len(value))
		copy(new_bucket, value)
		m.Buckets[time_window][index] = new_bucket
	} else {
		m.Aggregate(item, value)
	}
	return nil
}

func (m *MonitorWorker) Aggregate(storedValue []byte, newValue []byte) error {
	if len(storedValue) != len(newValue) {
		return serrors.New("slices need equal length")
	}
	for i := 0; i < len(storedValue); i++ {
		storedValue[i] ^= newValue[i]
	}
	return nil
}

func (m *MonitorWorker) ComputeTimeWindowIndex(flowID int) uint8 {

	return uint8(flowID & 0x3)
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
