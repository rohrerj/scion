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

package slayers

import (
	"encoding/binary"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

const baseFabridLen int = 8
const fabridMetadataLen int = 4

type FabridOption struct {
	PktTimestamp     time.Time
	PacketID         uint32
	HopfieldMetadata []FabridHopfieldMetadata
	FirstInfoField   *path.InfoField
}

type FabridHopfieldMetadata struct {
	EncryptedPolicyID  uint8
	HopValidationField [3]byte
}

func (f *FabridHopfieldMetadata) DecodeFabridHopfieldMetadata(b []byte) error {
	if len(b) < fabridMetadataLen {
		return serrors.New("Buffer too small to decode metadata",
			"is", len(b), "expected", fabridMetadataLen)
	}
	f.decodeFabridHopfieldMetadata(b)
	return nil
}

func (f *FabridHopfieldMetadata) decodeFabridHopfieldMetadata(b []byte) {
	f.EncryptedPolicyID = uint8(b[0])
	copy(f.HopValidationField[:], b[1:4])
}

func (f *FabridHopfieldMetadata) SerializeTo(b []byte) error {
	if len(b) < fabridMetadataLen {
		return serrors.New("Buffer too small to serialize metadata",
			"is", len(b), "expected", fabridMetadataLen)
	}
	f.serializeTo(b)
	return nil
}

func (f *FabridHopfieldMetadata) serializeTo(b []byte) {
	b[0] = byte(f.EncryptedPolicyID)
	copy(b[1:4], f.HopValidationField[:])
}

// decodeTimestampFromBytes decodes the timestamp from bytes.
// Requires that the first info field is already decoded.
func (f *FabridOption) decodeFabridTimestampFromBytes(b []byte) {
	fabridTs := uint64(binary.BigEndian.Uint32(b) & 0x7FFFFFF) // take only the right 27bit
	ts := fabridTs + 1000*uint64(f.FirstInfoField.Timestamp)
	f.PktTimestamp = time.Unix(0, int64(time.Millisecond)*int64(ts))
}

func (p *FabridOption) serializeFabridTimestampTo(b []byte) {
	fabridTs := uint32(p.PktTimestamp.UnixMilli()-int64(p.FirstInfoField.Timestamp)*1000) & 0x7FFFFFF
	binary.BigEndian.PutUint32(b, fabridTs)
}

// parseBase parses the timestamp and the packet ID. Additionally it
// verifies that the length of the raw Fabrid option is large enough.
func (f *FabridOption) decodeBase(b []byte, inf *path.InfoField, base *scion.Base) error {
	if f == nil {
		return serrors.New("Fabrid option must not be nil")
	}
	if inf == nil {
		return serrors.New("Infofield must not be nil")
	}
	if base == nil {
		return serrors.New("Base must not be nil")
	}
	if len(b) < fabridLen(base.NumHops) {
		return serrors.New("Raw Fabrid option too short", "is", len(b),
			"expected", fabridLen(base.NumHops))
	}
	if base.NumHops > 61 {
		// The size of FABRID is limited to 255 bytes because of the HBH option length field
		// 8 bytes + 61 * 4 bytes = 252 bytes
		return serrors.New("Fabrid is not supported for paths consisting of more than 61 hopfields")
	}
	f.FirstInfoField = inf
	f.decodeFabridTimestampFromBytes(b[0:4])
	f.PacketID = binary.BigEndian.Uint32(b[4:8])
	return nil
}

// DecodeForCurrentHop uses the scion meta header to determine the current hop
// and decodes only the FABRID timestamp, packetID and the metadata of the current
// hop and stores it in f.HopfieldMetadata[0].
func (f *FabridOption) DecodeForCurrentHop(b []byte, inf *path.InfoField, base *scion.Base) error {
	if err := f.decodeBase(b, inf, base); err != nil {
		return err
	}
	byteIndex := baseFabridLen + int(base.PathMeta.CurrHF)*fabridMetadataLen
	md := FabridHopfieldMetadata{}
	md.decodeFabridHopfieldMetadata(b[byteIndex : byteIndex+fabridMetadataLen])
	f.HopfieldMetadata = []FabridHopfieldMetadata{
		md,
	}
	return nil
}

func (f *FabridOption) DecodeFull(b []byte, inf *path.InfoField, base *scion.Base) error {
	if err := f.decodeBase(b, inf, base); err != nil {
		return err
	}
	byteIndex := baseFabridLen
	f.HopfieldMetadata = make([]FabridHopfieldMetadata, base.NumHops)
	for i := 0; i < base.NumHops; i++ {
		md := FabridHopfieldMetadata{}
		md.decodeFabridHopfieldMetadata(b[byteIndex : byteIndex+fabridMetadataLen])
		f.HopfieldMetadata[i] = md
		byteIndex += fabridMetadataLen
	}
	return nil
}

func (f *FabridOption) SerializeTo(b []byte) error {
	if f == nil {
		return serrors.New("Fabrid option must not be nil")
	}
	if len(b) < fabridLen(len(f.HopfieldMetadata)) {
		return serrors.New("Buffer too short", "is", len(b),
			"expected", fabridLen(len(f.HopfieldMetadata)))
	}
	if f.FirstInfoField == nil {
		return serrors.New("First info field must not be nil")
	}
	if len(f.HopfieldMetadata) > 61 {
		// The size of FABRID is limited to 255 bytes because of the HBH option length field
		// 8 bytes + 61 * 4 bytes = 252 bytes
		return serrors.New("Fabrid is not supported for paths consisting of more than 61 hopfields")
	}
	f.serializeFabridTimestampTo(b[0:4])
	binary.BigEndian.PutUint32(b[4:8], f.PacketID)
	byteIndex := baseFabridLen
	for _, md := range f.HopfieldMetadata {
		md.serializeTo(b[byteIndex : byteIndex+4])
		byteIndex += 4
	}
	return nil
}

func fabridLen(numHopfields int) int {
	return baseFabridLen + numHopfields*fabridMetadataLen
}

func ParseFabridOptionFullExtension(o *EndToEndOption, inf *path.InfoField, base *scion.Base) (FabridOption, error) {
	if o.OptType != OptTypeFabrid {
		return FabridOption{},
			serrors.New("Wrong option type", "expected", OptTypeFabrid, "actual", o.OptType)
	}
	f := FabridOption{}
	if err := f.DecodeFull(o.OptData, inf, base); err != nil {
		return FabridOption{}, err
	}
	return f, nil
}

func ParseFabridOptionCurrentHop(o *EndToEndOption, inf *path.InfoField, base *scion.Base) (FabridOption, error) {
	if o.OptType != OptTypeFabrid {
		return FabridOption{},
			serrors.New("Wrong option type", "expected", OptTypeFabrid, "actual", o.OptType)
	}
	f := FabridOption{}
	if err := f.DecodeForCurrentHop(o.OptData, inf, base); err != nil {
		return FabridOption{}, err
	}
	return f, nil
}
