// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package marketplace

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/scionproto/scion/marketplace/db"
	"github.com/scionproto/scion/marketplace/storage"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
)

const (
	RESID_BITS       = 22
	MAX_DURATION_SEC = math.MaxUint16
	AkBufferSize     = 16
)

type RedemptionService struct {
	SendChannel    chan *hummingbird.RedeemAssetFromASRequest
	Pending        map[uint64]chan *hummingbird.RedeemAssetFromASResponse
	UpdateChannel  chan *RedemptionDelegationUpdate
	client         *RedemptionServerPeer
	store          *storage.MarketplaceStorage
	cipher         cipher.Block
	resLimit       uint32
	resIdStore     ReservationIdStore
	encodingPoints []uint64
	mtx            sync.RWMutex
}

type RedemptionDelegationUpdate struct {
	ExpirationTime     time.Time
	ReservationIdLimit uint32
	Key                []byte
	EncodingPoints     []uint64
}

type ReservationIdStore interface {
	Init(limit uint32, r []*db.UsedReservation) error
	Next(start uint64, end uint64) (uint32, error)
	Migrate(newLimit uint32) error
	Close() error
}

func NewRedemptionService(ctx context.Context, client *RedemptionServerPeer, store *storage.MarketplaceStorage, ia addr.IA, initState RedemptionDelegationUpdate, sendCh chan *hummingbird.RedeemAssetFromASRequest,
	pending map[uint64]chan *hummingbird.RedeemAssetFromASResponse) (*RedemptionService, error) {
	slices.Sort(initState.EncodingPoints)
	blockCipher, err := aes.NewCipher(initState.Key)
	if err != nil {
		return nil, err
	}
	s := &RedemptionService{
		SendChannel:    sendCh,
		Pending:        pending,
		UpdateChannel:  make(chan *RedemptionDelegationUpdate, 1),
		store:          store,
		cipher:         blockCipher,
		resLimit:       initState.ReservationIdLimit,
		encodingPoints: initState.EncodingPoints,
		client:         client,
		resIdStore:     &UsedIDStore{},
	}
	now := time.Now()
	res, err := s.store.FindUsedReservations(ctx, &db.UsedReservationsQuery{
		IA:       ia,
		StartsAt: now.UTC().Format(time.RFC3339),
		StopsAt:  initState.ExpirationTime.Format(time.RFC3339),
	})
	if err != nil {
		return nil, err
	}
	err = s.resIdStore.Init(initState.ReservationIdLimit, res)
	if err != nil {
		return nil, err
	}
	go s.readRoutine()
	return s, nil
}

func (s *RedemptionService) readRoutine() {
	var err error
	for {
		select {
		case u := <-s.UpdateChannel:
			if u.ExpirationTime.After(time.Now()) {
				s.client.closeConnection()
				return
			}
			if err = s.handleUpdate(u); err != nil {
				fmt.Println(err)
				return
			}
		case r := <-s.SendChannel:
			if err = s.handleRequest(r); err != nil {
				fmt.Println(err)
			}
		}
	}
}

func (s *RedemptionService) handleUpdate(u *RedemptionDelegationUpdate) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	err := s.resIdStore.Migrate(u.ReservationIdLimit)
	if err != nil {
		return err
	}
	slices.Sort(u.EncodingPoints)
	s.encodingPoints = u.EncodingPoints
	s.cipher, err = aes.NewCipher(u.Key)
	return err
}

func (s *RedemptionService) handleRequest(r *hummingbird.RedeemAssetFromASRequest) error {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	resId, err := s.resIdStore.Next(uint64(r.StartsAt.Seconds), uint64(r.StopsAt.Seconds))
	if err != nil {
		return err
	}

	unixStart := uint32(r.StartsAt.Seconds)
	unixEnd := uint32(r.StopsAt.Seconds)
	durSeconds := unixEnd - unixStart
	encoded_bw := s.encodeBandwidth(r.Bw)

	var buff [16]byte
	ak := s.deriveAuthKey(s.cipher, resId, encoded_bw, uint16(r.IngressId), uint16(r.EgressId), unixStart, uint16(durSeconds), buff[:])
	s.client.mtx.Lock()
	ch, ok := s.Pending[r.RequestId]
	if ok {
		ch <- &hummingbird.RedeemAssetFromASResponse{
			ResInfo: &hummingbird.ReservationInfo{
				ResId:               resId,
				BwRounded:           s.encodingPoints[encoded_bw],
				BwDataplaneEncoding: uint32(encoded_bw),
			},
			Ak:        ak,
			RequestId: r.RequestId,
		}
		close(ch)
		delete(s.client.pending, r.RequestId)
	}
	s.client.mtx.Unlock()
	return nil
}

func (s *RedemptionService) encodeBandwidth(bw uint64) uint16 {
	return uint16(sort.Search(len(s.encodingPoints), func(i int) bool {
		return s.encodingPoints[i] >= bw
	}))
}

// DeriveAuthKey: copied and slightly modified from https://github.com/juagargi/scion/blob/hummingbird-endhost/pkg/slayers/path/hummingbird/mac.go
func (s *RedemptionService) deriveAuthKey(
	block cipher.Block,
	resId uint32,
	bw uint16,
	in uint16,
	eg uint16,
	startTime uint32,
	resDuration uint16,
	buffer []byte,
) []byte {

	// Bounds check.
	_ = buffer[AkBufferSize-1]

	// Prepare input buffer.
	binary.BigEndian.PutUint16(buffer[0:2], in)
	binary.BigEndian.PutUint16(buffer[2:4], eg)
	binary.BigEndian.PutUint32(buffer[4:8], resId<<10|uint32(bw))
	binary.BigEndian.PutUint32(buffer[8:12], startTime)
	binary.BigEndian.PutUint16(buffer[12:14], resDuration)
	binary.BigEndian.PutUint16(buffer[14:16], 0) //padding

	// Should XOR input with iv, but we use iv = 0 => identity
	block.Encrypt(buffer[0:16], buffer[0:16])
	return buffer[0:AkBufferSize]
}

// this is a very simple reservation ID store that never reuses the same ID and does not
// care about start or end
type UsedIDStore struct {
	usedIds map[uint32]struct{}
	next    uint32
	limit   uint32
}

func (s *UsedIDStore) Init(limit uint32, r []*db.UsedReservation) error {
	clear(s.usedIds)
	s.limit = limit
	s.next = 0
	for _, res := range r {
		s.usedIds[res.Id] = struct{}{}
	}
	return nil
}

func (s *UsedIDStore) Next(start uint64, end uint64) (uint32, error) {
	for ; s.next < s.limit; s.next++ {
		_, found := s.usedIds[s.next]
		if !found {
			return s.next, nil
		}
	}
	return 0, serrors.New("no free reservation id")
}

func (s *UsedIDStore) Migrate(newLimit uint32) error {
	if s.next < newLimit {
		s.limit = newLimit
		return nil
	}
	return serrors.New("newLimit too small")
}

func (s *UsedIDStore) Close() error {
	clear(s.usedIds)
	return nil
}
