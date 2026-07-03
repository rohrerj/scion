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
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/scionproto/scion/marketplace/db"
	"github.com/scionproto/scion/marketplace/storage"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	hbird "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
)

const (
	AkBufferSize = 16
)

type RedemptionService struct {
	SendChannel chan *hummingbird.RedeemAssetFromASRequest
	Pending     map[uint64]chan *hummingbird.RedeemAssetFromASResponse
	// The update channel is used to propagate updates to the redemption service
	// like different secret key or updated expiration date
	// The result of the update is send over the UpdateResultChannel, which MUST
	// be consumed by the entity who send the update over the UpdateChannel.
	UpdateChannel       chan *RedemptionDelegationUpdate
	UpdateResultChannel chan error
	client              *RedemptionServerPeer
	store               *storage.MarketplaceStorage
	cipher              cipher.Block
	resLimit            uint32
	resIdStore          ReservationIdStore
	encodingPoints      []uint32
	expiration          time.Time
}

type RedemptionDelegationUpdate struct {
	ExpirationTime     time.Time
	ReservationIdLimit uint32
	Key                []byte
	EncodingPoints     []uint32
}

type RedemptionDelegationUpdateResult struct {
	ExpirationTime time.Time
	OK             bool
}

type ReservationIdStore interface {
	Init(limit uint32, r []*db.UsedReservation) error
	Next(start uint64, end uint64) (uint32, error)
	Migrate(newLimit uint32, r []*db.UsedReservation) error
	Close() error
}

func NewRedemptionService(ctx context.Context, client *RedemptionServerPeer, store *storage.MarketplaceStorage, ia addr.IA, initState *RedemptionDelegationUpdate, sendCh chan *hummingbird.RedeemAssetFromASRequest,
	pending map[uint64]chan *hummingbird.RedeemAssetFromASResponse) (*RedemptionService, error) {
	slices.Sort(initState.EncodingPoints)
	blockCipher, err := aes.NewCipher(initState.Key)
	if err != nil {
		return nil, err
	}
	s := &RedemptionService{
		SendChannel:         sendCh,
		Pending:             pending,
		UpdateChannel:       make(chan *RedemptionDelegationUpdate),
		UpdateResultChannel: make(chan error),
		store:               store,
		cipher:              blockCipher,
		resLimit:            initState.ReservationIdLimit,
		encodingPoints:      initState.EncodingPoints,
		client:              client,
		expiration:          initState.ExpirationTime,
		resIdStore:          &UsedIDStore{},
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
			if u.ExpirationTime.Before(time.Now()) {
				s.UpdateResultChannel <- nil
				return
			}
			s.UpdateResultChannel <- s.handleUpdate(u)
		case r := <-s.SendChannel:
			if s.expiration.Before(time.Now()) {
				select {
				case s.SendChannel <- r:
				default:
				}
				return
			}
			if err = s.handleRequest(r); err != nil {
				fmt.Println(err)
				return
			}
		}
	}
}

func (s *RedemptionService) handleUpdate(u *RedemptionDelegationUpdate) error {
	var res []*db.UsedReservation
	var err error
	if u.ExpirationTime != s.expiration {
		now := time.Now()
		res, err = s.store.FindUsedReservations(context.TODO(), &db.UsedReservationsQuery{
			IA:       s.client.ia,
			StartsAt: now.UTC().Format(time.RFC3339),
			StopsAt:  u.ExpirationTime.Format(time.RFC3339),
		})
		if err != nil {
			return err
		}
		s.expiration = u.ExpirationTime
	}
	err = s.resIdStore.Migrate(u.ReservationIdLimit, res)
	if err != nil {
		return err
	}
	slices.Sort(u.EncodingPoints)
	s.encodingPoints = u.EncodingPoints
	s.cipher, err = aes.NewCipher(u.Key)
	return err
}

func (s *RedemptionService) handleRequest(r *hummingbird.RedeemAssetFromASRequest) error {
	resId, err := s.resIdStore.Next(uint64(r.StartsAt.Seconds), uint64(r.StopsAt.Seconds))
	if err != nil {
		return err
	}

	unixStart := uint32(r.StartsAt.Seconds)
	unixEnd := uint32(r.StopsAt.Seconds)
	durSeconds := unixEnd - unixStart
	encoded_bw := s.encodeBandwidth(r.Bandwidth)

	var buff [16]byte
	ak := hbird.DeriveAuthKey(s.cipher, resId, encoded_bw, uint16(r.IngressId), uint16(r.EgressId), unixStart, uint16(durSeconds), buff[:])
	s.client.mtx.Lock()
	ch, ok := s.Pending[r.RequestId]
	if ok {
		ch <- &hummingbird.RedeemAssetFromASResponse{
			ResInfo: &hummingbird.ReservationInfo{
				ReservationId:       resId,
				BandwithRounded:     s.encodingPoints[encoded_bw],
				BwDataplaneEncoding: uint32(encoded_bw),
			},
			AuthenticationKey: ak,
			RequestId:         r.RequestId,
		}
		close(ch)
		delete(s.client.pending, r.RequestId)
	}
	s.client.mtx.Unlock()
	return nil
}

func (s *RedemptionService) encodeBandwidth(bw uint32) uint16 {
	return uint16(sort.Search(len(s.encodingPoints), func(i int) bool {
		return s.encodingPoints[i] >= bw
	}))
}

// this is a very simple reservation ID store that never reuses the same ID and does not
// care about start or end
type UsedIDStore struct {
	usedIds map[uint32]struct{}
	next    uint32
	limit   uint32
}

func (s *UsedIDStore) Init(limit uint32, r []*db.UsedReservation) error {
	s.usedIds = make(map[uint32]struct{})
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
			s.usedIds[s.next] = struct{}{}
			tmp := s.next
			s.next++
			return tmp, nil
		}
	}
	return 0, serrors.New("no free reservation id")
}

func (s *UsedIDStore) Migrate(newLimit uint32, r []*db.UsedReservation) error {
	if s.next > newLimit {
		return serrors.New("newLimit too small")
	}
	if r != nil {
		clear(s.usedIds)
		s.next = 0
		for _, res := range r {
			s.usedIds[res.Id] = struct{}{}
		}
	}
	s.limit = newLimit
	return nil
}

func (s *UsedIDStore) Close() error {
	clear(s.usedIds)
	return nil
}
