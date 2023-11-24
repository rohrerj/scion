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

package path

import (
	"context"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
)

type FabridConfig struct {
	LocalIA         addr.IA
	LocalAddr       string
	DestinationIA   addr.IA
	DestinationAddr string
}

type FABRID struct {
	Raw              []byte
	keys             []drkey.ASHostKey
	keyBytes         [][]byte
	sigmas           [][]byte
	pathKey          drkey.HostHostKey
	drkeyFn          func(context.Context, drkey.ASHostMeta) (drkey.ASHostKey, error)
	drkeyPathFn      func(context.Context, drkey.HostHostMeta) (drkey.HostHostKey, error)
	conf             *FabridConfig
	counter          uint32
	baseTimestamp    uint32
	tmpBuffer        []byte
	ias              []addr.IA
	identifierBuffer []byte
	fabridBuffer     []byte
}

func NewFABRIDDataplanePath(p SCION, interfaces []snet.PathInterface, policyIDs []uint8, conf *FabridConfig) (*FABRID, error) {
	ias := make([]addr.IA, len(interfaces))
	for i, pathInterface := range interfaces {
		ias[i] = pathInterface.IA
	}
	f := &FABRID{
		conf:             conf,
		ias:              ias,
		keys:             make([]drkey.ASHostKey, len(ias)),
		keyBytes:         make([][]byte, len(ias)),
		sigmas:           make([][]byte, len(ias)),
		tmpBuffer:        make([]byte, 64),
		identifierBuffer: make([]byte, 8),
		fabridBuffer:     make([]byte, 8+4*len(ias)),
		Raw:              append([]byte(nil), p.Raw...),
	}
	var decoded scion.Decoded
	if err := decoded.DecodeFromBytes(p.Raw); err != nil {
		return nil, serrors.WrapStr("decoding path", err)
	}
	for i, hop := range decoded.HopFields {
		f.sigmas[i] = make([]byte, 6)
		copy(f.sigmas[i], hop.Mac[:])
	}
	f.baseTimestamp = decoded.InfoFields[0].Timestamp
	return f, nil
}

func (f *FABRID) RegisterDRKeyFetcher(fn func(context.Context, drkey.ASHostMeta) (drkey.ASHostKey, error),
	fn2 func(context.Context, drkey.HostHostMeta) (drkey.HostHostKey, error)) {

	f.drkeyFn = fn
	f.drkeyPathFn = fn2
}

func (f *FABRID) SetPath(s *slayers.SCION) error {
	var sp scion.Raw
	if err := sp.DecodeFromBytes(f.Raw); err != nil {
		return err
	}
	s.Path, s.PathType = &sp, sp.Type()
	return nil
}
func (f *FABRID) SetExtensions(s *slayers.SCION, p *snet.PacketInfo) error {
	if s == nil {
		return serrors.New("scion layer is nil")
	}
	if p == nil {
		return serrors.New("packet info is nil")
	}
	if p.HbhExtension == nil {
		p.HbhExtension = &slayers.HopByHopExtn{}
	}
	now := time.Now().Truncate(time.Millisecond)
	err := f.renewExpiredKeys(now)
	if err != nil {
		return err
	}
	identifierOption := &extension.IdentifierOption{
		Timestamp:     now,
		BaseTimestamp: f.baseTimestamp,
		PacketID:      f.counter,
	}
	fabridOption := &extension.FabridOption{
		HopfieldMetadata: make([]*extension.FabridHopfieldMetadata, len(f.ias)),
	}
	for i := 0; i < len(f.ias); i++ {
		meta := &extension.FabridHopfieldMetadata{}
		meta.FabridEnabled = true
		// TODO: replace with correct policy ID
		policyID := &fabrid.FabridPolicyID{
			ID:     0,
			Global: false,
		}
		encPolicyID, err := fabrid.EncryptPolicyID(policyID, identifierOption, f.keyBytes[i])
		if err != nil {
			return err
		}
		meta.EncryptedPolicyID = encPolicyID
		fabridOption.HopfieldMetadata[i] = meta
	}
	err = fabrid.InitValidators(fabridOption, identifierOption, s, f.tmpBuffer, f.pathKey.Key[:], f.keyBytes, f.sigmas)
	if err != nil {
		return err
	}
	err = identifierOption.Serialize(f.identifierBuffer)
	if err != nil {
		return err
	}
	err = fabridOption.SerializeTo(f.fabridBuffer)
	if err != nil {
		return err
	}
	fabridLength := 4 + 4*len(f.ias)
	p.HbhExtension.Options = append(p.HbhExtension.Options,
		&slayers.HopByHopOption{
			OptType:      slayers.OptTypeIdentifier,
			OptData:      f.identifierBuffer,
			OptDataLen:   8,
			ActualLength: 8,
		},
		&slayers.HopByHopOption{
			OptType:      slayers.OptTypeFabrid,
			OptData:      f.fabridBuffer[:fabridLength],
			OptDataLen:   uint8(fabridLength),
			ActualLength: fabridLength,
		})
	f.counter++
	return nil
}

func (f *FABRID) renewExpiredKeys(t time.Time) error {
	for i, key := range f.keys {
		if key.Epoch.NotAfter.Before(t) {
			// key is expired, renew it
			newKey, err := f.fetchKey(f.ias[i])
			if err != nil {
				return err
			}
			f.keys[i] = newKey
			f.keyBytes[i] = newKey.Key[:]
		}
	}
	if f.pathKey.Epoch.NotAfter.Before(t) {
		// key is expired, renew it
		newKey, err := f.fetchPathKey()
		if err != nil {
			return err
		}
		f.pathKey = newKey
	}
	return nil
}

func (f *FABRID) fetchPathKey() (drkey.HostHostKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key, err := f.drkeyPathFn(ctx, drkey.HostHostMeta{
		Validity: time.Now(),
		SrcIA:    f.conf.LocalIA,
		SrcHost:  f.conf.LocalAddr,
		DstIA:    f.conf.DestinationIA,
		DstHost:  f.conf.DestinationAddr,
		ProtoId:  drkey.FABRID,
	})
	if err != nil {
		return drkey.HostHostKey{}, err
	}
	return key, nil
}

func (f *FABRID) fetchKey(ia addr.IA) (drkey.ASHostKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key, err := f.drkeyFn(ctx, drkey.ASHostMeta{
		Validity: time.Now(),
		SrcIA:    ia,
		DstIA:    f.conf.LocalIA,
		DstHost:  f.conf.LocalAddr,
		ProtoId:  drkey.FABRID,
	})
	if err != nil {
		return drkey.ASHostKey{}, err
	}
	return key, nil
}
