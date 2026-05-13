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
	"net"
	"syscall"

	"github.com/scionproto/scion/pkg/private/serrors"
)

type snapPacketConn struct {
	net.PacketConn
}

func (c snapPacketConn) SyscallConn() (syscall.RawConn, error) {
	return nil, serrors.New("snap connections do not support SyscallConn")
}
func (c snapPacketConn) SetReadBuffer(bytes int) error {
	// nop
	return nil
}
func (c snapPacketConn) SetWriteBuffer(bytes int) error {
	// nop
	return nil
}
