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
	"hash"

	"github.com/dchest/cmac"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	ext "github.com/scionproto/scion/pkg/slayers/extension"
)

type FabridPolicyID struct {
	ID     uint8
	Global bool
}

const FabridMacInputSize int = 40

//  MAC xored key input:
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Identifier (8B)                                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| SrcISD (2B)             | SrcAS (6B)                |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//	MAC input:
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Sigma (6B)                                          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         |ePolicyID(1B)| sHostLen(1B)|
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Source Host Address (4-16 Bytes)                    |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func computeFabridHVF(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, resultBuffer []byte,
	key []byte, sigma []byte) error {
	if len(key) != 16 {
		return serrors.New("Wrong key length", "expected", 16, "actual", len(key))
	}
	if len(sigma) != 6 {
		return serrors.New("Wrong sigma length", "expected", 6, "actual", len(sigma))
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
	srcIABytes, _ := s.SrcIA.MarshalText()

	xoredKey := make([]byte, len(key))
	for i := 0; i < 8; i++ {
		xoredKey[i] = key[i] ^ tmpBuffer[i]
	}
	for i := 0; i < 8; i++ {
		xoredKey[i+8] = key[i+8] ^ srcIABytes[i]
	}

	srcAddr := s.RawSrcAddr
	srcAddrLen := len(srcAddr)
	usedBufferLength := 8 + srcAddrLen
	copy(tmpBuffer[0:6], sigma[0:6])
	tmpBuffer[6] = f.EncryptedPolicyID
	tmpBuffer[7] = byte(s.SrcAddrType.Length())
	copy(tmpBuffer[8:usedBufferLength], srcAddr)

	macBlock(xoredKey, tmpBuffer[24:40], tmpBuffer[:usedBufferLength], resultBuffer[:])
	return nil
}

func ComputeBaseHVF(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, sigma []byte) error {
	computedHVF := make([]byte, 16)
	err := computeFabridHVF(f, id, s, tmpBuffer, computedHVF, key, sigma)
	if err != nil {
		return err
	}
	computedHVF[0] &= 0x3f // ignore first two (left) bits
	copy(f.HopValidationField[:], computedHVF[0:3])
	return nil
}

func ComputeVerifiedHVF(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, sigma []byte) error {
	computedHVF := make([]byte, 16)
	err := computeFabridHVF(f, id, s, tmpBuffer, computedHVF, key, sigma)
	if err != nil {
		return err
	}
	computedHVF[3] &= 0x3f // ignore first two (left) bits
	copy(f.HopValidationField[:], computedHVF[3:6])
	return nil
}

func VerifyAndUpdate(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, sigma []byte) error {
	computedHVF := make([]byte, 16)
	err := computeFabridHVF(f, id, s, tmpBuffer, computedHVF, key, sigma)
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
	if policyID >= 0x80 { // first bit is 1
		fp.Global = true
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
func InitValidators(f *ext.FabridOption, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, pathKey []byte, keys [][]byte, sigmas [][]byte) error {

	outBuffer := make([]byte, 16)
	pathValidatorBuf := make([]byte, ext.FabridMetadataLen*len(f.HopfieldMetadata))
	for i, meta := range f.HopfieldMetadata {
		err := computeFabridHVF(meta, id, s, tmpBuffer, outBuffer, keys[i], sigmas[i])
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
		pathValidatorBuf[i*ext.FabridMetadataLen] = meta.EncryptedPolicyID
		copy(pathValidatorBuf[i*ext.FabridMetadataLen+1:i*ext.FabridMetadataLen+4], outBuffer[3:6])
	}
	mac, err := initCMAC(pathKey)
	if err != nil {
		return err
	}
	mac.Write(pathValidatorBuf)
	copy(f.PathValidator[:4], mac.Sum([]byte{}))
	return nil
}

func VerifyPath(f *ext.FabridOption, key []byte) error {
	buf := make([]byte, ext.FabridMetadataLen*len(f.HopfieldMetadata))
	for i := 0; i < len(f.HopfieldMetadata); i++ {
		f.HopfieldMetadata[i].SerializeTo(buf[i*ext.FabridMetadataLen : (i+1)*ext.FabridMetadataLen])
		buf[i*ext.FabridMetadataLen+1] &= 0x3f // ignore first two (left) bits
	}
	mac, err := initCMAC(key)
	if err != nil {
		return err
	}
	mac.Write(buf)
	computedPathValidator := mac.Sum([]byte{})
	if !bytes.Equal(computedPathValidator[:4], f.PathValidator[:]) {
		return serrors.New("Path validator is invalid")
	}
	return nil
}

func initCMAC(key []byte) (hash.Hash, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, serrors.WrapStr("unable to initialize AES cipher", err)
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, serrors.WrapStr("unable to initialize Mac", err)
	}
	return mac, nil
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
