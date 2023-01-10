// Copyright 2023 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package processing

import (
	"net"
	"syscall"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"golang.org/x/net/ipv4"
)

type packetForwarderContainer struct {
	Length       uint32
	ForwardTasks []chan []byte
}

type packetForwarder struct {
	addr         *net.UDPAddr
	metrics      *ColigateMetrics
	batchSize    int
	ForwardTasks chan []byte
}

func NewPacketForwarder(addr *net.UDPAddr, batchSize int, ch chan []byte,
	metrics *ColigateMetrics) *packetForwarder {
	return &packetForwarder{
		addr:         addr,
		batchSize:    batchSize,
		metrics:      metrics,
		ForwardTasks: ch,
	}
}

// Starts the packet forwarder. This should be called in a new
// go routine.
func (p *packetForwarder) Start() error {
	workerPacketOutTotalPromCounter := p.metrics.WorkerPacketOutTotal
	workerPacketOutErrorPromCounter := p.metrics.WorkerPacketOutError
	writeMsgs := make([]ipv4.Message, p.batchSize)
	for i := 0; i < p.batchSize; i++ {
		writeMsgs[i].Buffers = [][]byte{make([]byte, bufSize)}
	}
	conn, err := net.DialUDP("udp", nil, p.addr)
	if err != nil {
		return serrors.New("PacketForwarder error while dialing", "err", err)
	}
	packetConn := ipv4.NewPacketConn(conn)
	defer packetConn.Close()
	exit := false
	for !exit {
		task := <-p.ForwardTasks
		if task == nil {
			return nil
		}
		writeMsgs[0].Buffers[0] = task
		i := 1
		// do we have more messages to send right now?
	loop:
		for i < p.batchSize {
			select {
			case task := <-p.ForwardTasks:
				if task == nil {
					// process all current packets, then exit
					exit = true
					break loop
				}
				writeMsgs[i].Buffers[0] = task
				i++
			default:
				break loop
			}
		}
		k, err := packetConn.WriteBatch(writeMsgs[:i], syscall.MSG_DONTWAIT)
		if err != nil {
			log.Debug("PacketForwarder error while sending", "err", err)
			workerPacketOutErrorPromCounter.Add(float64(i))
			continue
		}

		// check whether all packets have been sent or not
		if k != i {
			workerPacketOutErrorPromCounter.Add(float64(i - k))
		}
		workerPacketOutTotalPromCounter.Add(float64(k))
	}
	return nil
}
