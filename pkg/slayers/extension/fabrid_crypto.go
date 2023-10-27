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

package extension

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"hash"

	"github.com/dchest/cmac"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

type FabridPolicyID struct {
	ID     uint8
	Global bool
}

const FabridMacInputSize int = 40

// MAC key: key xor (Identifier ++ SrcISD-AS)
// MAC input: Sigma ++ EncPolicyID ++ SrcHostAddrLength ++ SrcHostAddress
func (f *FabridHopfieldMetadata) computeFabridHVF(id *IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, resultBuffer [16]byte,
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
	id.Serialize(tmpBuffer[0:8])
	srcIABytes, _ := s.SrcIA.MarshalText()

	xoredKey := make([]byte, len(key))
	for i := 0; i < 8; i++ {
		xoredKey[i] = key[i] ^ tmpBuffer[i]
	}
	for i := 0; i < 8; i++ {
		xoredKey[i] = key[i+8] ^ srcIABytes[i]
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

func (f *FabridHopfieldMetadata) ComputeBaseHVF(id *IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, sigma []byte) error {
	computedHVF := [16]byte{}
	err := f.computeFabridHVF(id, s, tmpBuffer, computedHVF, key, sigma)
	if err != nil {
		return err
	}
	computedHVF[0] &= 0x7f // ignore QoS bit
	copy(f.HopValidationField[:], computedHVF[0:3])
	return nil
}

func (f *FabridHopfieldMetadata) ComputeVerifiedHVF(id *IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, sigma []byte) error {
	computedHVF := [16]byte{}
	err := f.computeFabridHVF(id, s, tmpBuffer, computedHVF, key, sigma)
	if err != nil {
		return err
	}
	computedHVF[3] &= 0x7f //ignore QoS bit
	copy(f.HopValidationField[:], computedHVF[3:6])
	return nil
}

func (f *FabridHopfieldMetadata) VerifyAndUpdate(id *IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, sigma []byte) error {
	computedHVF := [16]byte{}
	err := f.computeFabridHVF(id, s, tmpBuffer, computedHVF, key, sigma)
	if err != nil {
		return err
	}
	computedHVF[0] &= 0x7f //ignore QoS bit
	if !bytes.Equal(computedHVF[:3], f.HopValidationField[:]) {
		return serrors.New("HVF is not valid")
	}
	computedHVF[3] &= 0x7f //ignore QoS bit
	copy(f.HopValidationField[:], computedHVF[3:6])
	return nil
}

func (f *FabridHopfieldMetadata) ComputePolicyID(id *IdentifierOption,
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

func (f *FabridPolicyID) EncryptPolicyID(id *IdentifierOption,
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
func (f *FabridOption) InitValidators(id *IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, pathKey []byte, keys [][]byte, sigmas [][]byte) error {

	outBuffer := [16]byte{}
	pathValidatorBuf := make([]byte, fabridMetadataLen*len(f.HopfieldMetadata))
	for i, meta := range f.HopfieldMetadata {
		err := meta.computeFabridHVF(id, s, tmpBuffer, outBuffer, keys[i], sigmas[i])
		if err != nil {
			return err
		}
		outBuffer[0] &= 0x7f //ignore QoS bit
		outBuffer[3] &= 0x7f //ignore QoS bit
		copy(meta.HopValidationField[:3], outBuffer[:3])
		pathValidatorBuf[i*fabridMetadataLen] = meta.EncryptedPolicyID
		copy(pathValidatorBuf[i*fabridMetadataLen+1:i*fabridMetadataLen+4], outBuffer[3:6])
	}
	mac, err := initCMAC(pathKey)
	if err != nil {
		return err
	}
	mac.Write(pathValidatorBuf)
	copy(f.PathValidator[:4], mac.Sum([]byte{}))
	return nil
}

func (f *FabridOption) VerifyPath(key []byte) error {
	buf := make([]byte, fabridMetadataLen*len(f.HopfieldMetadata))
	for i := 0; i < len(f.HopfieldMetadata); i++ {
		f.HopfieldMetadata[i].serializeTo(buf[i*fabridMetadataLen : (i+1)*fabridMetadataLen])
		buf[i*fabridMetadataLen+1] &= 0x7f //ignore QoS bit
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
