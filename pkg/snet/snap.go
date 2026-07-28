// Copyright 2026 ETH Zurich
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

package snet

import (
	"context"
	"net"
	"syscall"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snap"
)

type SnapConn struct {
	SCMPHandler    SCMPHandler
	metrics        SCIONPacketConnMetrics
	tunnel         *snap.SnapTunnel
	readTimer      *time.Timer
	writeTimer     *time.Timer
	sendChannel    chan []byte
	receiveChannel chan []byte
}

func (n *SCIONNetwork) newSnapConn(ctx context.Context) (*SnapConn, error) {
	tunnel, err := snap.NewSnapTunnel(ctx, n.Topology.Snap.ControlApi, snap.WithTokenProvider(n.Topology.Snap.TokenProvider))
	if err != nil {
		return nil, err
	}
	conn := &SnapConn{
		tunnel:         tunnel,
		sendChannel:    tunnel.SendChannel(),
		receiveChannel: tunnel.ReceiveChannel(),
		SCMPHandler:    n.SCMPHandler,
		metrics:        n.PacketConnMetrics,
	}
	return conn, nil
}

func (s *SnapConn) Close() error {
	metrics.CounterInc(s.metrics.Closes)
	return s.tunnel.Close()
}

func (s *SnapConn) LocalAddr() net.Addr {
	return s.tunnel.LocalAddr
}

func (s *SnapConn) NextHop() *net.UDPAddr {
	return s.tunnel.DataplaneAddr
}

// Reads a packet from the SNAP tunnel. 'ov' is always the SNAP dataplane endpoint.
func (s *SnapConn) ReadFrom(pkt *Packet, ov *net.UDPAddr) error {
	pkt.Prepare()
	addr := *s.tunnel.DataplaneAddr
	*ov = addr
	var b []byte
	if s.readTimer != nil {
		select {
		case b = <-s.receiveChannel:
			copy(pkt.Bytes, b)
		case t := <-s.readTimer.C:
			return serrors.New("read deadline", "time", t)
		}
	} else {
		b = <-s.receiveChannel
		copy(pkt.Bytes, b)
	}
	n := len(b)
	metrics.CounterAdd(s.metrics.ReadBytes, float64(n))
	metrics.CounterInc(s.metrics.ReadPackets)
	pkt.Bytes = pkt.Bytes[:n]
	if err := pkt.Decode(); err != nil {
		metrics.CounterInc(s.metrics.ParseErrors)
		log.Debug("decoding packet", "error", err)
		return err
	}
	if scmp, ok := pkt.Payload.(SCMPPayload); ok {
		if s.SCMPHandler == nil {
			metrics.CounterInc(s.metrics.SCMPErrors)
			return serrors.New("scmp packet received, but no handler found",
				"type_code", slayers.CreateSCMPTypeCode(scmp.Type(), scmp.Code()),
				"src", pkt.Source)
		}
		if err := s.SCMPHandler.Handle(pkt); err != nil {
			return err
		}
	}
	return nil
}

func (s *SnapConn) SetDeadline(t time.Time) error {
	s.SetReadDeadline(t)
	s.SetWriteDeadline(t)
	return nil
}

func (s *SnapConn) SetReadDeadline(t time.Time) error {
	if s.readTimer != nil {
		s.readTimer.Reset(time.Until(t))
	} else {
		s.readTimer = time.NewTimer(time.Until(t))
	}
	return nil
}

func (s *SnapConn) SetWriteDeadline(t time.Time) error {
	if s.writeTimer != nil {
		s.writeTimer.Reset(time.Until(t))
	} else {
		s.writeTimer = time.NewTimer(time.Until(t))
	}
	return nil
}

func (s *SnapConn) SyscallConn() (syscall.RawConn, error) {
	return nil, serrors.New("snap does not support syscallConn")
}

// WriteTo queues a packet for sending through the SNAP tunnel.
func (s *SnapConn) WriteTo(pkt *Packet, _ *net.UDPAddr) error {
	if err := pkt.Serialize(); err != nil {
		return serrors.Wrap("serialize SCION packet", err)
	}
	if len(pkt.Bytes) > s.tunnel.MTU() {
		return serrors.New("SCION packet too big. Either path or payload too long.", "max size", s.tunnel.MTU(), "current size", len(pkt.Bytes))
	}
	b := make([]byte, len(pkt.Bytes))
	copy(b, pkt.Bytes)
	if s.writeTimer != nil {
		select {
		case s.sendChannel <- b:
		case t := <-s.writeTimer.C:
			return serrors.New("write deadline", "time", t)
		}
	} else {
		s.sendChannel <- b
	}
	metrics.CounterAdd(s.metrics.WriteBytes, float64(len(pkt.Bytes)))
	metrics.CounterInc(s.metrics.WritePackets)
	return nil
}
