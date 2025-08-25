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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

type HashRegion []byte

type Parser struct {
	cmnHdrPlusAddrHdrLen int
	currInfAndHf         byte
	infSegIDs            [3]uint16
	numInfs              int
	HashRegions          [2]HashRegion
}

// Parses a SCION packet and sets all values that are expected to change between two on-path ASes to zero.
// It will keep track of all values it has set to zero and can undo the changes by calling UndoZero() with the same packet.
// We will always have 2 Hash Regions, one time the scion common header + address header + path, and the second region
// is everything else except the hbh extension which is not part of any hash region.
func (p *Parser) Parse(packet []byte) error {
	pathType := path.Type(packet[8])
	if pathType != scion.PathType {
		return serrors.New("path type not yet supported")
	}
	addrHeaderLen := 2*addr.IABytes + slayers.AddrType(packet[9]>>4&0xF).Length() + slayers.AddrType(packet[9]&0xF).Length()
	p.cmnHdrPlusAddrHdrLen = slayers.CmnHdrLen + addrHeaderLen
	hdrLenInBytes := packet[5] << 2
	p.currInfAndHf = packet[p.cmnHdrPlusAddrHdrLen]
	metaHdr := scion.MetaHdr{}
	metaHdr.DecodeFromBytes(packet[p.cmnHdrPlusAddrHdrLen:])
	p.numInfs = 1
	if metaHdr.SegLen[1] != 0 {
		p.numInfs = 2
	}
	if metaHdr.SegLen[2] != 0 {
		p.numInfs = 3
	}
	switch p.numInfs {
	case 1:
		{
			p.infSegIDs[0] = binary.BigEndian.Uint16(packet[p.cmnHdrPlusAddrHdrLen+6 : p.cmnHdrPlusAddrHdrLen+8])
			binary.BigEndian.PutUint16(packet[p.cmnHdrPlusAddrHdrLen+6:p.cmnHdrPlusAddrHdrLen+8], 0)
		}
	case 2:
		{
			p.infSegIDs[0] = binary.BigEndian.Uint16(packet[p.cmnHdrPlusAddrHdrLen+6 : p.cmnHdrPlusAddrHdrLen+8])
			binary.BigEndian.PutUint16(packet[p.cmnHdrPlusAddrHdrLen+6:p.cmnHdrPlusAddrHdrLen+8], 0)
			p.infSegIDs[1] = binary.BigEndian.Uint16(packet[p.cmnHdrPlusAddrHdrLen+10 : p.cmnHdrPlusAddrHdrLen+12])
			binary.BigEndian.PutUint16(packet[p.cmnHdrPlusAddrHdrLen+10:p.cmnHdrPlusAddrHdrLen+12], 0)
		}
	case 3:
		{
			p.infSegIDs[0] = binary.BigEndian.Uint16(packet[p.cmnHdrPlusAddrHdrLen+6 : p.cmnHdrPlusAddrHdrLen+8])
			binary.BigEndian.PutUint16(packet[p.cmnHdrPlusAddrHdrLen+6:p.cmnHdrPlusAddrHdrLen+8], 0)
			p.infSegIDs[1] = binary.BigEndian.Uint16(packet[p.cmnHdrPlusAddrHdrLen+10 : p.cmnHdrPlusAddrHdrLen+12])
			binary.BigEndian.PutUint16(packet[p.cmnHdrPlusAddrHdrLen+10:p.cmnHdrPlusAddrHdrLen+12], 0)
			p.infSegIDs[2] = binary.BigEndian.Uint16(packet[p.cmnHdrPlusAddrHdrLen+14 : p.cmnHdrPlusAddrHdrLen+16])
			binary.BigEndian.PutUint16(packet[p.cmnHdrPlusAddrHdrLen+14:p.cmnHdrPlusAddrHdrLen+16], 0)
		}
	}

	nextHdr := slayers.L4ProtocolType(packet[4])
	p.HashRegions[0] = HashRegion(packet[:hdrLenInBytes])
	if nextHdr < 200 { //some non SCION nextHdr, probably just payload?
		p.HashRegions[1] = HashRegion(packet[hdrLenInBytes:])
		return nil
	} else {
		nextHdrHashRegion, err := p.parseNextHdr(nextHdr, packet[hdrLenInBytes:])
		if err != nil {
			return err
		}
		p.HashRegions[1] = nextHdrHashRegion
		return nil
	}
}

func (p *Parser) parseNextHdr(hdr slayers.L4ProtocolType, buf []byte) (HashRegion, error) {
	// We have to check whether this header is a hop by hop extension because that one has to be treated differently
	// because the on-path border routers might modify its content depending on the options present.
	// There might also be an end to end extension present, but the specification says that if both hbh and e2e
	// extensions are present, e2e has to come after hbh and since the e2e extension is not supposed to be modified
	// by the border routers we can treat everything that comes after the hbh extension as "payload" of some sort
	if hdr == slayers.HopByHopClass { //hop by hop extension
		// for now we don't hash the content of the hbh extension. The presence of the hbh extension however is recorded
		// because NextHdr in the scion common header is part of the hash
		nextHdr := slayers.L4ProtocolType(buf[0])
		actualLength := (int(buf[1]) + 1) * 4
		return p.parseNextHdr(nextHdr, buf[actualLength:])
	} else {
		return HashRegion(buf), nil
	}
}

// UndoZero will revert all zeroed memory using the state of the most recently parsed packet
func (p *Parser) UndoZero(packet []byte) {
	packet[p.cmnHdrPlusAddrHdrLen] = p.currInfAndHf
	switch p.numInfs {
	case 1:
		{
			binary.BigEndian.PutUint16(packet[p.cmnHdrPlusAddrHdrLen+6:p.cmnHdrPlusAddrHdrLen+8], p.infSegIDs[0])
		}
	case 2:
		{
			binary.BigEndian.PutUint16(packet[p.cmnHdrPlusAddrHdrLen+6:p.cmnHdrPlusAddrHdrLen+8], p.infSegIDs[0])
			binary.BigEndian.PutUint16(packet[p.cmnHdrPlusAddrHdrLen+10:p.cmnHdrPlusAddrHdrLen+12], p.infSegIDs[1])
		}
	case 3:
		{
			binary.BigEndian.PutUint16(packet[p.cmnHdrPlusAddrHdrLen+6:p.cmnHdrPlusAddrHdrLen+8], p.infSegIDs[0])
			binary.BigEndian.PutUint16(packet[p.cmnHdrPlusAddrHdrLen+10:p.cmnHdrPlusAddrHdrLen+12], p.infSegIDs[1])
			binary.BigEndian.PutUint16(packet[p.cmnHdrPlusAddrHdrLen+14:p.cmnHdrPlusAddrHdrLen+16], p.infSegIDs[2])
		}
	}
}
