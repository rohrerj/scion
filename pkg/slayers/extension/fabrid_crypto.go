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
	"encoding/binary"
	"hash"

	"github.com/dchest/cmac"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

type FabridPolicyID struct {
	ID     uint8
	Global bool
}

func (f *FabridHopfieldMetadata) ComputeFabridHVF(id *IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, resultBuffer [6]byte,
	key []byte, sigma []byte) error {
	if len(key) != len(sigma) {
		return serrors.New("Both keys must have the same length", "len(key)",
			len(key), "len(sigma)", len(sigma))
	}
	xoredKey := make([]byte, len(key))
	for i := 0; i < len(key); i++ {
		xoredKey[i] = key[i] ^ sigma[i]
	}

	srcAS := uint64(s.SrcIA.AS())
	srcAddr := s.RawSrcAddr
	srcAddrLen := len(srcAddr)
	macInputLength := 17 + srcAddrLen
	if len(tmpBuffer) < macInputLength {
		return serrors.New("buffer too small", "expected",
			macInputLength, "got", len(tmpBuffer))
	}
	err := id.Serialize(tmpBuffer[0:8])
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint64(tmpBuffer[8:16], srcAS)
	copy(tmpBuffer[16:16+srcAddrLen], srcAddr)
	tmpBuffer[16+srcAddrLen] = f.EncryptedPolicyID

	mac, err := initCMAC(xoredKey)
	if err != nil {
		return err
	}
	_, err = mac.Write(tmpBuffer)
	if err != nil {
		return err
	}
	macBytes := mac.Sum([]byte{})
	copy(resultBuffer[:], macBytes[:6])

	return nil
}

func (f *FabridHopfieldMetadata) VerifyAndUpdate(id *IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, sigma []byte) error {
	computedHVF := [6]byte{}
	err := f.ComputeFabridHVF(id, s, tmpBuffer, computedHVF, key, sigma)
	if err != nil {
		return err
	}
	if !bytes.Equal(computedHVF[:3], f.HopValidationField[:]) {
		return serrors.New("HVF is not valid")
	}
	copy(f.HopValidationField[:], computedHVF[3:6])
	return nil
}

func (f *FabridHopfieldMetadata) ComputePolicyID(id *IdentifierOption,
	key []byte) (FabridPolicyID, error) {

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return FabridPolicyID{}, err
	}
	buf := make([]byte, identifierLength)
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
	buf := make([]byte, identifierLength)
	if err = id.Serialize(buf); err != nil {
		return 0, err
	}
	cipher.Encrypt(buf, buf)
	policyID := f.ID ^ buf[0]
	return policyID, nil
}

func (f *FabridOption) VerifyPath(s *slayers.SCION, key [16]byte) {

}

func (f *FabridOption) ComputePathValidator(s *slayers.SCION, key [16]byte) {

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
