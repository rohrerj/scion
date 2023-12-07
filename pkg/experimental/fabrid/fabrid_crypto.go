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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	ext "github.com/scionproto/scion/pkg/slayers/extension"
)

type FabridPolicyID struct {
	ID uint8
}

const FabridMacInputSize int = 46

//	MAC input:
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Identifier (8B)                                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Cons Ingress (2B)        |  Cons Egress (2B)        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |ePolicyID(1B)|sHostLen(1B)| SrcHostAddr (4-16 B)     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func computeFabridHVF(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, resultBuffer []byte,
	key []byte, ingress uint16, egress uint16) error {
	if len(key) != 16 {
		return serrors.New("Wrong key length", "expected", 16, "actual", len(key))
	}
	if len(tmpBuffer) < FabridMacInputSize {
		return serrors.New("tmpBuffer too small", "expected",
			FabridMacInputSize, "actual", len(tmpBuffer))
	}
	if len(resultBuffer) < 16 {
		return serrors.New("resultBuffer too small", "expected",
			16, "actual", len(resultBuffer))
	}

	id.Serialize(tmpBuffer[0:8])

	srcAddr := s.RawSrcAddr
	requiredLen := 14 + len(srcAddr)
	binary.BigEndian.PutUint16(tmpBuffer[8:10], ingress)
	binary.BigEndian.PutUint16(tmpBuffer[10:12], egress)
	tmpBuffer[12] = f.EncryptedPolicyID
	tmpBuffer[13] = byte(s.SrcAddrType.Length())
	copy(tmpBuffer[14:requiredLen], srcAddr)

	macBlock(key, tmpBuffer[30:46], tmpBuffer[:requiredLen], resultBuffer[:])
	return nil
}

func ComputeBaseHVF(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, ingress uint16, egress uint16) error {
	computedHVF := make([]byte, 16)
	err := computeFabridHVF(f, id, s, tmpBuffer, computedHVF, key, ingress, egress)
	if err != nil {
		return err
	}
	computedHVF[0] &= 0x3f // ignore first two (left) bits
	copy(f.HopValidationField[:], computedHVF[0:3])
	return nil
}

func ComputeVerifiedHVF(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, ingress uint16, egress uint16) error {
	computedHVF := make([]byte, 16)
	err := computeFabridHVF(f, id, s, tmpBuffer, computedHVF, key, ingress, egress)
	if err != nil {
		return err
	}
	computedHVF[3] &= 0x3f // ignore first two (left) bits
	copy(f.HopValidationField[:], computedHVF[3:6])
	return nil
}

func VerifyAndUpdate(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, ingress uint16, egress uint16) error {
	computedHVF := make([]byte, 16)
	err := computeFabridHVF(f, id, s, tmpBuffer, computedHVF, key, ingress, egress)
	if err != nil {
		return err
	}
	computedHVF[0] &= 0x3f // ignore first two (left) bits
	if !bytes.Equal(computedHVF[:3], f.HopValidationField[:]) {
		return serrors.New("HVF is not valid")
	}
	computedHVF[3] &= 0x3f // ignore first two (left) bits
	copy(f.HopValidationField[:], computedHVF[3:6])
	return nil
}

func ComputePolicyID(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	key []byte) (FabridPolicyID, error) {

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return FabridPolicyID{}, err
	}
	buf := make([]byte, aes.BlockSize)
	if err = id.Serialize(buf); err != nil {
		return FabridPolicyID{}, err
	}
	cipher.Encrypt(buf, buf)
	policyID := f.EncryptedPolicyID ^ buf[0]
	fp := FabridPolicyID{
		ID: policyID,
	}
	return fp, nil
}

func EncryptPolicyID(f *FabridPolicyID, id *ext.IdentifierOption,
	key []byte) (uint8, error) {

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}
	buf := make([]byte, aes.BlockSize)
	if err = id.Serialize(buf); err != nil {
		return 0, err
	}
	cipher.Encrypt(buf, buf)
	policyID := f.ID ^ buf[0]
	return policyID, nil
}

// InitValidators sets all HVFs of the FABRID option and computes the
// path validator.
func InitValidators(f *ext.FabridOption, id *ext.IdentifierOption, s *slayers.SCION, tmpBuffer []byte, pathKey []byte,
	asHostKeys map[addr.IA]drkey.ASHostKey, asAsKeys map[addr.IA]drkey.Level1Key, ias []addr.IA, ingresses []uint16, egresses []uint16) error {

	outBuffer := make([]byte, 16)
	for i, meta := range f.HopfieldMetadata {
		var key drkey.Key
		if meta.ASLevelKey {
			asAsKey, found := asAsKeys[ias[i]]
			if !found {
				return serrors.New("InitValidators expected AS to AS key but was not in dictionary", "AS", ias[i])
			}
			key = asAsKey.Key
		} else {
			asHostKey, found := asHostKeys[ias[i]]
			if !found {
				return serrors.New("InitValidators expected AS to AS key but was not in dictionary", "AS", ias[i])
			}
			key = asHostKey.Key
		}

		err := computeFabridHVF(meta, id, s, tmpBuffer, outBuffer, key[:], ingresses[i], egresses[i])
		if err != nil {
			return err
		}
		outBuffer[0] &= 0x3f // ignore first two (left) bits
		outBuffer[3] &= 0x3f // ignore first two (left) bits
		if meta.FabridEnabled {
			copy(meta.HopValidationField[:3], outBuffer[:3])
		} else {
			copy(meta.HopValidationField[:3], outBuffer[3:6])
		}
	}
	return nil
}

var zeroBlock [16]byte

func macBlock(key []byte, tmp []byte, src []byte, dst []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return serrors.WrapStr("unable to initialize AES cipher", err)
	}
	if len(dst) < 16 {
		return serrors.New("Dst length is invalid", "expected", 16, "actual", len(dst))
	}
	if len(src) == 0 {
		return serrors.New("Src length cannot be 0")
	}
	if len(tmp) < 16 {
		return serrors.New("tmp length is invalid", "expected", 16, "actual", len(tmp))
	}
	encryptor := cipher.NewCBCEncrypter(block, zeroBlock[:])
	paddingLength := (16 - len(src)%16) % 16
	blockCount := len(src) / block.BlockSize()

	if blockCount != 0 {
		encryptor.CryptBlocks(dst, src[:16*blockCount])
	}
	if paddingLength != 0 {
		copy(tmp, src[16*blockCount:])
		copy(tmp[16-paddingLength:], zeroBlock[:paddingLength])
		encryptor.CryptBlocks(dst, tmp)
	}
	return nil
}
