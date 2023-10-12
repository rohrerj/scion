// Copyright 2023 ETH Zurich
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

// The Identifier option format is as follows:
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   NextHdr     |     ExtLen    |  OptType = 3  |  OptLen = 8   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | R R R R R |              Timestamp                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Packet ID                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

package extension

import (
	"encoding/binary"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

const identifierLength int = 8

type IdentifierOption struct {
	// Timestamp with 1 ms precision
	Timestamp time.Time
	// The packet ID
	PacketID uint32

	// The base timestamp. Usually the timestamp of the first info field.
	BaseTimestamp uint32
}

func (id *IdentifierOption) decodeTimestampFromBytes(b []byte) {
	fabridTs := uint64(binary.BigEndian.Uint32(b) & 0x7FFFFFF) // take only the right 27bit
	ts := fabridTs + 1000*uint64(id.BaseTimestamp)
	id.Timestamp = time.Unix(0, int64(time.Millisecond)*int64(ts))
}

func (id *IdentifierOption) serializeTimestampTo(b []byte) {
	fabridTs := uint32(id.Timestamp.UnixMilli()-int64(id.BaseTimestamp)*1000) & 0x7FFFFFF
	binary.BigEndian.PutUint32(b, fabridTs)
}

func (id *IdentifierOption) decode(b []byte) error {
	if len(b) < identifierLength {
		return serrors.New("raw data too short", "expected", identifierLength, "actual", len(b))
	}
	id.decodeTimestampFromBytes(b[0:4])
	id.PacketID = binary.BigEndian.Uint32(b[4:8])

	return nil
}

func (id *IdentifierOption) Serialize(b []byte) error {
	if id == nil {
		return serrors.New("identifier option must not be nil")
	}
	if len(b) < identifierLength {
		return serrors.New("buffer too short", "expected", identifierLength, "actual", len(b))
	}
	id.serializeTimestampTo(b[0:4])
	binary.BigEndian.PutUint32(b[4:8], id.PacketID)
	return nil
}

func ParseIdentifierOption(o *slayers.EndToEndOption, baseTimestamp uint32) (IdentifierOption, error) {
	if o.OptType != slayers.OptTypeIdentifier {
		return IdentifierOption{},
			serrors.New("Wrong option type", "expected", slayers.OptTypeIdentifier, "actual", o.OptType)
	}
	identifier := IdentifierOption{
		BaseTimestamp: baseTimestamp,
	}
	if err := identifier.decode(o.OptData); err != nil {
		return IdentifierOption{}, err
	}
	return identifier, nil
}
