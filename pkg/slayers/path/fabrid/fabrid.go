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

package fabrid

import (
	"encoding/binary"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

const PathType path.Type = 6
const BaseHeaderLen int = 8 + scion.MetaLen
const InfoFieldLen int = path.InfoLen
const HopFieldLen int = path.HopLen + 4

const MinPathLen int = BaseHeaderLen + InfoFieldLen + HopFieldLen

func RegisterPath() {
	path.RegisterPath(path.Metadata{
		Type: PathType,
		Desc: "FABRID",
		New: func() path.Path {
			return &FabridPath{}
		},
	})
}

type FabridPath struct {
	PktTimestamp time.Time
	PacketID     uint32
	Base         scion.Base
	InfoFields   []InfoField
	HopFields    []HopField
}

type InfoField struct {
	path.InfoField
}

type HopField struct {
	path.HopField
	EncryptedPolicyID  uint8
	HopValidationField [3]byte
}

func (i *InfoField) DecodeFromBytes(b []byte) error {
	return i.InfoField.DecodeFromBytes(b)
}

func (i *InfoField) SerializeTo(b []byte) error {
	return i.InfoField.SerializeTo(b)
}

func (h *HopField) DecodeFromBytes(b []byte) error {
	if len(b) < HopFieldLen {
		return serrors.New("HopField raw too short", "expected", HopFieldLen, "actual", len(b))
	}
	err := h.HopField.DecodeFromBytes(b[:path.HopLen])
	if err != nil {
		return err
	}
	h.EncryptedPolicyID = uint8(b[path.HopLen])
	copy(h.HopValidationField[:], b[path.HopLen+1:HopFieldLen])
	return nil
}

func (h *HopField) SerializeTo(b []byte) error {
	if len(b) < HopFieldLen {
		return serrors.New("Buffer too small to serialize hopfield",
			"expected", HopFieldLen, "actual", len(b))
	}
	err := h.HopField.SerializeTo(b[:path.HopLen])
	if err != nil {
		return err
	}
	b[path.HopLen] = byte(h.EncryptedPolicyID)
	copy(b[path.HopLen+1:HopFieldLen], h.HopValidationField[:])

	return nil
}

// decodeTimestampFromBytes decodes the timestamp from bytes.
// Requires that the first info field is already decoded.
func (p *FabridPath) decodeTimestampFromBytes(b []byte) error {
	if len(b) != 4 {
		return serrors.New("Timestamp raw has invalid length", "expected", 4, "actual", len(b))
	}
	fabridTs := binary.BigEndian.Uint64(b) & 0x7FFFFFF // take only the right 27bit
	ts := fabridTs + 1000*uint64(p.InfoFields[0].Timestamp)
	p.PktTimestamp = time.Unix(0, time.Hour.Milliseconds()*int64(ts))
	return nil
}

// serializes the timestamp as a relative FABRID timestamp to the
// byte array. The reserved bits will be overwritten.
func (p *FabridPath) serializeTimestampTo(b []byte) error {
	if len(b) != 4 {
		return serrors.New("Buffer too small to serialize timestamp", "expected", 4, "actual", len(b))
	}
	fabridTs := uint32(p.PktTimestamp.UnixMilli()-int64(p.InfoFields[0].Timestamp)*1000) & 0x7FFFFFF
	binary.BigEndian.PutUint32(b, fabridTs)
	return nil
}

// DecodeFromBytes decodes a FABRID path from a byte slice.
func (p *FabridPath) DecodeFromBytes(b []byte) error {
	if p == nil {
		return serrors.New("Fabrid path must not be nil")
	}
	if len(b) < MinPathLen {
		return serrors.New("Raw fabrid path is too short", "is",
			len(b), "minimum", MinPathLen)
	}
	p.PacketID = binary.BigEndian.Uint32(b[4:8])
	err := p.Base.DecodeFromBytes(b[8:12])
	if err != nil {
		return err
	}
	expectedHeaderLen := BaseHeaderLen + p.Base.NumINF*InfoFieldLen +
		p.Base.NumHops*HopFieldLen
	if len(b) < expectedHeaderLen {
		return serrors.New("Raw fabrid path is too short", "is",
			len(b), "expected", expectedHeaderLen)
	}
	byteIndex := BaseHeaderLen
	p.InfoFields = make([]InfoField, p.Base.NumINF)
	for i := 0; i < p.Base.NumINF; i++ {
		err = p.InfoFields[i].DecodeFromBytes(b[byteIndex : byteIndex+InfoFieldLen])
		if err != nil {
			return err
		}
		byteIndex += InfoFieldLen
	}
	p.HopFields = make([]HopField, p.Base.NumHops)
	for i := 0; i < p.Base.NumHops; i++ {
		err = p.HopFields[i].DecodeFromBytes(b[byteIndex : byteIndex+HopFieldLen])
		if err != nil {
			return err
		}
		byteIndex += HopFieldLen
	}
	p.decodeTimestampFromBytes(b[:4])
	return nil
}

// Len returns the length of the FABRID path in bytes.
func (p *FabridPath) Len() int {
	return BaseHeaderLen + len(p.InfoFields)*InfoFieldLen +
		len(p.HopFields)*HopFieldLen
}

// Reverse reverses the FABRID path by constructing a reversed SCION path
func (p *FabridPath) Reverse() (path.Path, error) {
	// TODO(rohrerj)
	return nil, nil
}

// SerializeTo serializes the FABRID path to a byte slice.
func (p *FabridPath) SerializeTo(b []byte) error {
	if len(b) < p.Len() {
		return serrors.New("Buffer too small", "is", len(b), "requires", p.Len())
	}
	err := p.serializeTimestampTo(b[0:4])
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint32(b[4:8], p.PacketID)
	err = p.Base.PathMeta.SerializeTo(b[8 : 8+scion.MetaLen])
	if err != nil {
		return err
	}
	byteIndex := BaseHeaderLen
	for i := 0; i < len(p.InfoFields); i++ {
		err = p.InfoFields[i].SerializeTo(b[byteIndex : byteIndex+InfoFieldLen])
		if err != nil {
			return err
		}
		byteIndex += InfoFieldLen
	}
	for i := 0; i < len(p.HopFields); i++ {
		err = p.HopFields[i].SerializeTo(b[byteIndex : byteIndex+HopFieldLen])
		if err != nil {
			return err
		}
		byteIndex += HopFieldLen
	}

	return nil
}

// Type returns the FABRID path type.
func (p *FabridPath) Type() path.Type {
	return PathType
}
