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

// The FABRID option format is as follows:
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   NextHdr     |     ExtLen    |  OptType = 4  |    OptLen     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Enc PolicyID  |F|A|   Hop Validation Field                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Enc PolicyID  |F|A|   Hop Validation Field                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    ....       | | |               ....                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Enc PolicyID  |F|A|   Hop Validation Field                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Path Validator                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

package extension

import (
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

const baseFabridLen int = 4
const FabridMetadataLen int = 4
const MaxSupportedFabridHops = 62

// The FABRID option requires the Identifier option to be present in the HBH header
// extension and defined before the FABRID option.
type FabridOption struct {
	HopfieldMetadata []*FabridHopfieldMetadata
	PathValidator    [4]byte
}

type FabridHopfieldMetadata struct {
	EncryptedPolicyID  uint8
	FabridEnabled      bool
	ASLevelKey         bool
	HopValidationField [3]byte
}

func (f *FabridHopfieldMetadata) DecodeFabridHopfieldMetadata(b []byte) error {
	if len(b) < FabridMetadataLen {
		return serrors.New("Buffer too small to decode metadata",
			"is", len(b), "expected", FabridMetadataLen)
	}
	f.decodeFabridHopfieldMetadata(b)
	return nil
}

func (f *FabridHopfieldMetadata) decodeFabridHopfieldMetadata(b []byte) {
	f.EncryptedPolicyID = uint8(b[0])
	copy(f.HopValidationField[:], b[1:4])
	if b[1]&0x80 > 0 {
		f.FabridEnabled = true
		if b[1]&0x40 > 0 {
			f.ASLevelKey = true
		}
	}
	f.HopValidationField[0] &= 0x3f
}

func (f *FabridHopfieldMetadata) SerializeTo(b []byte) error {
	if len(b) < FabridMetadataLen {
		return serrors.New("Buffer too small to serialize metadata",
			"is", len(b), "expected", FabridMetadataLen)
	}
	f.serializeTo(b)
	return nil
}

func (f *FabridHopfieldMetadata) serializeTo(b []byte) {
	b[0] = byte(f.EncryptedPolicyID)
	copy(b[1:4], f.HopValidationField[:])
	b[1] &= 0x3f // clear the first two (left) bits of the HVF
	if f.FabridEnabled {
		b[1] |= 0x80
		if f.ASLevelKey {
			b[1] |= 0x40
		}
	}
}

func (f *FabridOption) validate(b []byte, base *scion.Base) error {
	if f == nil {
		return serrors.New("Fabrid option must not be nil")
	}
	if base == nil {
		return serrors.New("Base must not be nil")
	}
	if len(b) < fabridLen(base.NumHops) {
		return serrors.New("Raw Fabrid option too short", "is", len(b),
			"expected", fabridLen(base.NumHops))
	}
	if base.NumHops > MaxSupportedFabridHops {
		// The size of FABRID is limited to 255 bytes because of the HBH option length field
		// 4 bytes + 62 * 4 bytes = 252 bytes
		return serrors.New("Fabrid is not supported for paths consisting of more than 62 hopfields")
	}
	return nil
}

// DecodeForCurrentHop uses the scion meta header to determine the current hop
// and decodes only the metadata of the current hop and stores it in f.HopfieldMetadata[0].
// The PathValidator will not be decoded.
func (f *FabridOption) DecodeForCurrentHop(b []byte, base *scion.Base) error {
	if err := f.validate(b, base); err != nil {
		return err
	}
	byteIndex := int(base.PathMeta.CurrHF) * FabridMetadataLen
	md := &FabridHopfieldMetadata{}
	md.decodeFabridHopfieldMetadata(b[byteIndex : byteIndex+FabridMetadataLen])
	f.HopfieldMetadata = []*FabridHopfieldMetadata{
		md,
	}
	return nil
}

func (f *FabridOption) DecodeFull(b []byte, base *scion.Base) error {
	if err := f.validate(b, base); err != nil {
		return err
	}
	byteIndex := 0
	f.HopfieldMetadata = make([]*FabridHopfieldMetadata, base.NumHops)
	for i := 0; i < base.NumHops; i++ {
		md := &FabridHopfieldMetadata{}
		md.decodeFabridHopfieldMetadata(b[byteIndex : byteIndex+FabridMetadataLen])
		f.HopfieldMetadata[i] = md
		byteIndex += FabridMetadataLen
	}
	copy(f.PathValidator[:], b[byteIndex:byteIndex+4])
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
	if len(f.HopfieldMetadata) > MaxSupportedFabridHops {
		// The size of FABRID is limited to 255 bytes because of the HBH option length field
		// 4 bytes + 62 * 4 bytes = 252 bytes
		return serrors.New("Fabrid is not supported for paths consisting of more than 62 hopfields")
	}
	byteIndex := 0
	for _, md := range f.HopfieldMetadata {
		md.serializeTo(b[byteIndex : byteIndex+4])
		byteIndex += 4
	}
	copy(b[byteIndex:byteIndex+4], f.PathValidator[:])
	return nil
}

func fabridLen(numHopfields int) int {
	return baseFabridLen + numHopfields*FabridMetadataLen
}

func ParseFabridOptionFullExtension(o *slayers.HopByHopOption, base *scion.Base) (*FabridOption, error) {
	if o.OptType != slayers.OptTypeFabrid {
		return nil,
			serrors.New("Wrong option type", "expected", slayers.OptTypeFabrid, "actual", o.OptType)
	}
	f := &FabridOption{}
	if err := f.DecodeFull(o.OptData, base); err != nil {
		return nil, err
	}
	return f, nil
}

func ParseFabridOptionCurrentHop(o *slayers.HopByHopOption, base *scion.Base) (*FabridOption, error) {
	if o.OptType != slayers.OptTypeFabrid {
		return nil,
			serrors.New("Wrong option type", "expected", slayers.OptTypeFabrid, "actual", o.OptType)
	}
	f := &FabridOption{}
	if err := f.DecodeForCurrentHop(o.OptData, base); err != nil {
		return nil, err
	}
	return f, nil
}
