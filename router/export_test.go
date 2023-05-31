// Copyright 2020 Anapaya Systems
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

package router

import (
	"net"

	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/private/topology"
)

var NewServices = newServices

type ProcessResult struct {
	processResult
}

func NewDP(
	external map[uint16]BatchConn,
	linkTypes map[uint16]topology.LinkType,
	internal BatchConn,
	internalNextHops map[uint16]*net.UDPAddr,
	svc map[addr.HostSVC][]*net.UDPAddr,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) *DataPlane {

	dp := &DataPlane{
		localIA:          local,
		external:         external,
		linkTypes:        linkTypes,
		neighborIAs:      neighbors,
		internalNextHops: internalNextHops,
		svc:              &services{m: svc},
		internal:         internal,
	}
	if err := dp.SetKey(key); err != nil {
		panic(err)
	}
	return dp
}

func (d *DataPlane) FakeStart() {
	d.running = true
}

func (d *DataPlane) ProcessPkt(ifID uint16, m *ipv4.Message) (ProcessResult, error) {

	p := newPacketProcessor(d, ifID)
	var srcAddr *net.UDPAddr
	// for real packets received from ReadBatch this is always non-nil.
	// Allow nil in test cases for brevity.
	if m.Addr != nil {
		srcAddr = m.Addr.(*net.UDPAddr)
	}
	result, err := p.processPkt(m.Buffers[0], srcAddr)
	return ProcessResult{processResult: result}, err
}

func (d *DataPlane) ComputeProcId(data []byte) (uint32, error) {
	return d.computeProcId(data)
}

func (d *DataPlane) ConfigureProcChannels(numProcRoutines int, queueSize int) []chan *packet {
	d.procRoutines = uint32(numProcRoutines)
	d.processorQueueSize = queueSize
	d.procChannels = make([]chan *packet, d.procRoutines)
	for i := 0; i < int(d.procRoutines); i++ {
		d.procChannels[i] = make(chan *packet, d.processorQueueSize)
	}
	return d.procChannels
}

func (d *DataPlane) SetRandomValue(v []byte) {
	d.randomValue = v
}

func (d *DataPlane) ConfigureBatchSize(size int) {
	d.interfaceBatchSize = size
}

func (d *DataPlane) InitializePacketPool(poolSize int) {
	d.packetPool = make(chan []byte, poolSize)
	for i := 0; i < poolSize; i++ {
		d.packetPool <- make([]byte, bufSize)
	}
}

func (d *DataPlane) InitReceiver(ni NetworkInterface) {
	d.initReceiver(ni)
}

func (d *DataPlane) CurrentPoolSize() int {
	return len(d.packetPool)
}

func (d *DataPlane) GetBufferFromPool() []byte {
	return <-d.packetPool
}

func (d *DataPlane) SendPacketToChannel(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, ingress uint16, raw []byte, ch chan *packet) {
	pkt := &packet{
		srcAddr:   srcAddr,
		dstAddr:   dstAddr,
		ingress:   ingress,
		rawPacket: raw,
	}
	ch <- pkt
}

func (d *DataPlane) ConfigureForwarder(ni NetworkInterface) chan *packet {
	if d.forwardChannels == nil {
		d.forwardChannels = make(map[uint16]chan *packet)
	}
	ch, found := d.forwardChannels[ni.InterfaceId]
	if !found {
		ch = make(chan *packet, d.interfaceBatchSize)
		d.forwardChannels[ni.InterfaceId] = ch
	}
	return ch
}

func (d *DataPlane) InitForwarder(ni NetworkInterface) {
	d.initForwarder(ni)
}

func (d *DataPlane) GetInternalInterface() BatchConn {
	return d.internal
}

func (d *DataPlane) SetRunning(b bool) {
	d.running = b
}

func ExtractServices(s *services) map[addr.HostSVC][]*net.UDPAddr {
	return s.m
}
