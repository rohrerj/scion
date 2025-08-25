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

	"github.com/scionproto/scion/pkg/experimental/pot/collector"
)

type Monitor struct {
	collector       collector.Collector
	hasher          hash.Hash
	Parser          Parser
	hashSampleSlice [256]byte
	Sampler         Sampler
}

func NewMonitor(collector collector.Collector, hasher hash.Hash) Monitor {
	m := Monitor{
		collector: collector,
		hasher:    hasher,
		Parser:    Parser{},
		Sampler:   &StrideSampler{},
	}
	return m
}

func (m *Monitor) ComputeTimeWindowIndex(flowID int8) uint8 {
	//TODO
	return 0
}

func (m *Monitor) HashAllPacket(packet []byte, hashBuffer []byte) error {
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
	m.hasher.Sum(hashBuffer[:0])
	m.Parser.UndoZero(packet)
	return nil
}

func (m *Monitor) HashPacket(packet []byte, hashBuffer []byte) error {
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
	if n <= len(m.hashSampleSlice) {
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
	m.hasher.Sum(hashBuffer[:0])
	m.Parser.UndoZero(packet)
	return nil
}

func (m *Monitor) Collect(ingress int, egress int, time_window int, hash int) {
	m.collector.Collect(ingress, egress, time_window, hash)
}
