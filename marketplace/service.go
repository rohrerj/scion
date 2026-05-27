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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type assetState int

const (
	Listed assetState = iota
	CheckedOut
	Bought
	BeingRedeemed
	BeingSplit
)

type Asset struct {
	Owner           string
	IA              addr.IA
	Bandwidth       uint64
	BandwidthMin    uint64
	StartAt         time.Time
	StopsAt         time.Time
	Price           uint64
	TimeGranularity uint64
	TimeMinDuration uint64
	IfIdIngress     *uint32
	IfIdEgress      *uint32
	mtx             sync.Mutex
	state           assetState
}

type Reservation struct {
	ResId     uint64
	Ia        addr.IA
	IngressId uint32
	EgressId  uint32
	Bw        uint64
	StartsAt  time.Time
	StopsAt   time.Time
	Ak        string
}

type Service struct {
	redemptionServerPeers map[addr.IA]*RedemptionServerPeer
	assets                map[uint64]*Asset
	currentAssetID        atomic.Uint64
	mtx                   sync.Mutex
	assetMtx              sync.RWMutex
	reservationMtx        sync.RWMutex
}

func NewService() *Service {
	return &Service{
		redemptionServerPeers: make(map[addr.IA]*RedemptionServerPeer),
		assets:                make(map[uint64]*Asset),
		currentAssetID:        atomic.Uint64{},
	}
}

func (s *Asset) TotalPrice() uint64 {
	splitDuration := uint64(s.StopsAt.Sub(s.StartAt).Seconds())
	return s.Price * splitDuration * s.Bandwidth
}

// locks the user and its reservations
func (s *Service) reservationOp(user *User, f func(*[]*Reservation) error) error {
	user.mtx.Lock()
	defer user.mtx.Unlock()
	return f(user.Reservations)
}

// requests global write lock for assets map, then runs provided function
func (s *Service) globalAssetsModOp(f func(map[uint64]*Asset) error) error {
	s.assetMtx.Lock()
	defer s.assetMtx.Unlock()
	return f(s.assets)
}

// requests a read lock for the global asset map, and a write lock
// for the specific asset, then performs provided function
func (s *Service) assetOp(assetID uint64, f func(*Asset) error) error {
	s.assetMtx.RLock()
	defer s.assetMtx.RUnlock()
	asset, found := s.assets[assetID]
	if !found {
		return serrors.New("asset not found")
	}
	asset.mtx.Lock()
	defer asset.mtx.Unlock()
	asset = s.assets[assetID]
	return f(asset)
}
func (a *Asset) assetType() hummingbird.AssetType {
	if a.IfIdIngress != nil {
		if a.IfIdEgress != nil {
			return hummingbird.AssetType_Interface_Pair
		}
		return hummingbird.AssetType_Ingress
	}
	return hummingbird.AssetType_Egress
}

func (s *Service) CombineAssets(ctx context.Context, req *connect.Request[hummingbird.CombineAssetRequest]) (*connect.Response[hummingbird.CombineAssetResponse], error) {
	user := ctx.Value("user").(*User)
	if req.Msg.AssetId_1 == req.Msg.AssetId_2 {
		return nil, connect.NewError(connect.CodeInvalidArgument, serrors.New("cannot combine asset with itself"))
	}
	var combinedAsset *Asset
	combineAsset := func(a1 *Asset, a2 *Asset) error {
		if a1.Owner != user.Username || a2.Owner != user.Username {
			return serrors.New("can only combine owned assets")
		}
		if a1.state != Bought || a2.state != Bought {
			return serrors.New("assets in wrong state for combining")
		}
		if a1.IA != a2.IA {
			return serrors.New("asset must have same IA")
		}
		if a1.assetType() != a2.assetType() {
			return serrors.New("asset must have same asset type")
		}
		if a1.IfIdIngress != nil && *a1.IfIdIngress != *a2.IfIdIngress {
			return serrors.New("asset must have same ingress")
		}
		if a1.IfIdEgress != nil && *a1.IfIdEgress != *a2.IfIdEgress {
			return serrors.New("asset must have same egress")
		}
		if a1.StartAt.Equal(a2.StartAt) && a1.StopsAt.Equal(a2.StopsAt) {
			combinedAsset = &Asset{
				state:           Bought,
				Owner:           user.Username,
				IA:              a1.IA,
				Bandwidth:       a1.Bandwidth + a2.Bandwidth,
				BandwidthMin:    min(a1.BandwidthMin, a2.BandwidthMin),
				StartAt:         a1.StartAt,
				StopsAt:         a1.StopsAt,
				Price:           0,
				TimeGranularity: max(a1.TimeGranularity, a2.TimeGranularity),
				TimeMinDuration: min(a1.TimeMinDuration, a2.TimeMinDuration),
				IfIdIngress:     a1.IfIdIngress,
				IfIdEgress:      a1.IfIdEgress,
			}
			return nil
		} else if a1.Bandwidth == a2.Bandwidth {
			if a1.StartAt.Equal(a2.StopsAt) {
				combinedAsset = &Asset{
					state:           Bought,
					Owner:           user.Username,
					IA:              a1.IA,
					Bandwidth:       a1.Bandwidth,
					BandwidthMin:    min(a1.BandwidthMin, a2.BandwidthMin),
					StartAt:         a2.StartAt,
					StopsAt:         a1.StopsAt,
					Price:           0,
					TimeGranularity: max(a1.TimeGranularity, a2.TimeGranularity),
					TimeMinDuration: min(a1.TimeMinDuration, a2.TimeMinDuration),
					IfIdIngress:     a1.IfIdIngress,
					IfIdEgress:      a1.IfIdEgress,
				}
				return nil
			} else if a2.StartAt.Equal(a1.StopsAt) {
				combinedAsset = &Asset{
					state:           Bought,
					Owner:           user.Username,
					IA:              a1.IA,
					Bandwidth:       a1.Bandwidth,
					BandwidthMin:    min(a1.BandwidthMin, a2.BandwidthMin),
					StartAt:         a1.StartAt,
					StopsAt:         a2.StopsAt,
					Price:           0,
					TimeGranularity: max(a1.TimeGranularity, a2.TimeGranularity),
					TimeMinDuration: min(a1.TimeMinDuration, a2.TimeMinDuration),
					IfIdIngress:     a1.IfIdIngress,
					IfIdEgress:      a1.IfIdEgress,
				}
				return nil
			}
		}
		return serrors.New("asset cannot be combined")
	}
	var err error
	if req.Msg.AssetId_1 < req.Msg.AssetId_2 {
		err = s.assetOp(req.Msg.AssetId_1, func(ingressAsset *Asset) error {
			return s.assetOp(req.Msg.AssetId_2, func(egressAsset *Asset) error {
				return combineAsset(ingressAsset, egressAsset)
			})
		})
	} else {
		err = s.assetOp(req.Msg.AssetId_2, func(egressAsset *Asset) error {
			return s.assetOp(req.Msg.AssetId_1, func(ingressAsset *Asset) error {
				return combineAsset(ingressAsset, egressAsset)
			})
		})
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	assetID := s.currentAssetID.Add(1)
	s.globalAssetsModOp(func(m map[uint64]*Asset) error {
		m[assetID] = combinedAsset
		delete(m, req.Msg.AssetId_1)
		delete(m, req.Msg.AssetId_2)
		return nil
	})
	return &connect.Response[hummingbird.CombineAssetResponse]{
		Msg: &hummingbird.CombineAssetResponse{
			AssetId: assetID,
		},
	}, nil
}

func (s *Service) SplitAsset(ctx context.Context, req *connect.Request[hummingbird.SplitAssetRequest]) (*connect.Response[hummingbird.SplitAssetResponse], error) {
	user := ctx.Value("user").(*User)
	var asset1, asset2 *Asset
	err := s.assetOp(req.Msg.AssetId, func(a *Asset) error {
		if a.Owner != user.Username {
			return serrors.New("splitting is only possible for owned assets")
		}
		if a.state != Bought {
			return serrors.New("splitting not possible in current asset state")
		}
		var requestedSplit []RequestedSplit
		switch req.Msg.SplitOption.(type) {
		case *hummingbird.SplitAssetRequest_BwSplit:
			reqBW := req.Msg.GetBwSplit()
			requestedSplit = []RequestedSplit{
				{
					ExactBandwidth: reqBW,
					ExactFrom:      a.StartAt,
					ExactTo:        a.StopsAt,
				},
				{
					ExactBandwidth: a.Bandwidth - reqBW,
					ExactFrom:      a.StartAt,
					ExactTo:        a.StopsAt,
				},
			}
		case *hummingbird.SplitAssetRequest_TimeSplit:
			reqTime := req.Msg.GetTimeSplit().AsTime()
			requestedSplit = []RequestedSplit{
				{
					ExactBandwidth: a.Bandwidth,
					ExactFrom:      a.StartAt,
					ExactTo:        reqTime,
				},
				{
					ExactBandwidth: a.Bandwidth,
					ExactFrom:      reqTime,
					ExactTo:        a.StopsAt,
				},
			}
		default:
			return serrors.New("invalid split request")
		}
		splitResult, err := SplitAsset(a, requestedSplit)
		if err != nil {
			return err
		}
		if !(len(splitResult.Bought) == 2 && len(splitResult.Unused) == 0 && len(splitResult.Remove) == 0) {
			return serrors.New("invalid split result")
		}
		a.state = BeingSplit
		asset1 = &Asset{
			state:           Bought,
			Owner:           a.Owner,
			IA:              a.IA,
			BandwidthMin:    a.BandwidthMin,
			Price:           a.Price,
			TimeGranularity: a.TimeGranularity,
			TimeMinDuration: a.TimeMinDuration,
			IfIdIngress:     a.IfIdIngress,
			IfIdEgress:      a.IfIdEgress,
			Bandwidth:       splitResult.Bought[0].Bandwidth,
			StartAt:         splitResult.Bought[0].StartAt,
			StopsAt:         splitResult.Bought[0].StopAt,
		}
		asset2 = &Asset{
			state:           Bought,
			Owner:           a.Owner,
			IA:              a.IA,
			BandwidthMin:    a.BandwidthMin,
			Price:           a.Price,
			TimeGranularity: a.TimeGranularity,
			TimeMinDuration: a.TimeMinDuration,
			IfIdIngress:     a.IfIdIngress,
			IfIdEgress:      a.IfIdEgress,
			Bandwidth:       splitResult.Bought[1].Bandwidth,
			StartAt:         splitResult.Bought[1].StartAt,
			StopsAt:         splitResult.Bought[1].StopAt,
		}
		return nil
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	assetID1 := s.currentAssetID.Add(1)
	assetID2 := s.currentAssetID.Add(1)
	s.globalAssetsModOp(func(m map[uint64]*Asset) error {
		m[assetID1] = asset1
		m[assetID2] = asset2
		delete(m, req.Msg.AssetId)
		return nil
	})
	return &connect.Response[hummingbird.SplitAssetResponse]{
		Msg: &hummingbird.SplitAssetResponse{
			AssetId_1: assetID1,
			AssetId_2: assetID2,
		},
	}, nil
}

func (s *Service) BuyAssets(ctx context.Context, req *connect.Request[hummingbird.BuyAssetsRequest]) (*connect.Response[hummingbird.BuyAssetsResponse], error) {
	fmt.Println("BuyAssets")
	user := ctx.Value("user").(*User)
	checkedOutAsset := make([]uint64, 0, 1)
	boughtAssets := make([]*hummingbird.BoughtAsset, 0, 1)
	undoCheckout := func() {
		for _, assetID := range checkedOutAsset {
			s.assetOp(assetID, func(a *Asset) error {
				a.state = Listed
				a.Owner = ""
				return nil
			})
		}
	}
	assetSplits := make(map[uint64][]RequestedSplit)
	for _, reqAsset := range req.Msg.Assets {
		err := s.assetOp(reqAsset.AssetId, func(a *Asset) error {
			if a.Owner != user.Username && a.state != Listed {
				return serrors.New("asset can currently not be bought")
			}
			if reqAsset.StartsAtExactly.AsTime().Truncate(time.Second).Before(a.StartAt) {
				return serrors.New("invalid validity")
			}
			if reqAsset.StopsAtExactly.AsTime().Truncate(time.Second).After(a.StopsAt) {
				return serrors.New("invalid validity")
			}
			a.state = CheckedOut
			a.Owner = user.Username //this is only temporary
			requestedSplits, found := assetSplits[reqAsset.AssetId]
			if !found {
				requestedSplits = make([]RequestedSplit, 0, 1)
				assetSplits[reqAsset.AssetId] = requestedSplits
			}
			assetSplits[reqAsset.AssetId] = append(requestedSplits, RequestedSplit{
				ExactFrom:      reqAsset.StartsAtExactly.AsTime().Truncate(time.Second),
				ExactTo:        reqAsset.StopsAtExactly.AsTime().Truncate(time.Second),
				ExactBandwidth: reqAsset.BwExact,
			})
			checkedOutAsset = append(checkedOutAsset, reqAsset.AssetId)
			return nil
		})
		if err != nil {
			undoCheckout()
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	var userOwnedAssetsToAdd []*Asset
	var unusedAssetsToAdd []*Asset

	for assetID, requestedSplits := range assetSplits {
		err := s.assetOp(assetID, func(a *Asset) error {
			res, err := SplitAsset(a, requestedSplits)
			if err != nil {
				return err
			}
			for _, seg := range res.Bought {
				userOwnedAssetsToAdd = append(userOwnedAssetsToAdd, &Asset{
					state:           Bought,
					Owner:           user.Username,
					IA:              a.IA,
					IfIdIngress:     a.IfIdIngress,
					IfIdEgress:      a.IfIdEgress,
					TimeGranularity: a.TimeGranularity,
					TimeMinDuration: a.TimeMinDuration,
					BandwidthMin:    a.BandwidthMin,
					Bandwidth:       seg.Bandwidth,
					StartAt:         seg.StartAt,
					StopsAt:         seg.StopAt,
					Price:           a.Price,
				})
			}
			for _, seg := range res.Unused {
				unusedAssetsToAdd = append(unusedAssetsToAdd, &Asset{
					state:           Listed,
					Owner:           "",
					IA:              a.IA,
					IfIdIngress:     a.IfIdIngress,
					IfIdEgress:      a.IfIdEgress,
					TimeGranularity: a.TimeGranularity,
					TimeMinDuration: a.TimeMinDuration,
					BandwidthMin:    a.BandwidthMin,
					Bandwidth:       seg.Bandwidth,
					StartAt:         seg.StartAt,
					StopsAt:         seg.StopAt,
					Price:           a.Price,
				})
			}
			for _, seg := range res.Remove {
				fmt.Println("remove", seg)
			}
			return err
		})
		if err != nil {
			undoCheckout()
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	costAcc := uint64(0)
	for _, asset := range userOwnedAssetsToAdd {
		costAcc += asset.TotalPrice()
	}
	if costAcc > req.Msg.MaxPrice {
		undoCheckout()
		return nil, connect.NewError(connect.CodeFailedPrecondition, serrors.New("Insufficient credit", "cost", costAcc))
	}
	user.mtx.Lock()
	defer user.mtx.Unlock()
	if user.Balance < costAcc {
		return nil, connect.NewError(connect.CodeFailedPrecondition, serrors.New("Insufficient credit", "cost", costAcc, "balance", user.Balance))
	}
	user.Balance -= costAcc
	s.globalAssetsModOp(func(m map[uint64]*Asset) error {
		for _, assetToAdd := range userOwnedAssetsToAdd {
			assetID := s.currentAssetID.Add(1)
			fmt.Println("add user owned asset: ", assetID)
			boughtAssets = append(boughtAssets, &hummingbird.BoughtAsset{AssetId: assetID})
			m[assetID] = assetToAdd
		}
		for _, assetToAdd := range unusedAssetsToAdd {
			assetID := s.currentAssetID.Add(1)
			fmt.Println("add unused asset: ", assetID)
			m[assetID] = assetToAdd
		}
		for _, assetToRemove := range checkedOutAsset {
			delete(m, assetToRemove)
			fmt.Println("removed asset: ", assetToRemove)
		}
		return nil
	})
	return &connect.Response[hummingbird.BuyAssetsResponse]{
		Msg: &hummingbird.BuyAssetsResponse{
			Assets: boughtAssets,
			Cost:   costAcc,
		},
	}, nil
}

func (s *Service) FetchReservations(ctx context.Context, req *connect.Request[hummingbird.FetchReservationsRequest]) (*connect.Response[hummingbird.FetchReservationsResponse], error) {
	user := ctx.Value("user").(*User)
	resp := make([]*hummingbird.Reservation, 0, 1)
	s.reservationOp(user, func(r *[]*Reservation) error {
		for _, res := range *r {
			if req.Msg.Ia != nil && uint64(res.Ia) != *req.Msg.Ia {
				continue
			}
			if req.Msg.StartsAt != nil && res.StartsAt.Before(req.Msg.StartsAt.AsTime()) {
				continue
			}
			if req.Msg.StopsAt != nil && res.StopsAt.After(req.Msg.StopsAt.AsTime()) {
				continue
			}
			if req.Msg.Bw != nil && res.Bw < *req.Msg.Bw {
				continue
			}
			if req.Msg.IngressId != nil && res.IngressId != *req.Msg.IngressId {
				continue
			}
			if req.Msg.EgressId != nil && res.EgressId != *req.Msg.EgressId {
				continue
			}
			resp = append(resp, &hummingbird.Reservation{
				ResId:     res.ResId,
				Ia:        uint64(res.Ia),
				IngressId: res.IngressId,
				EgressId:  res.EgressId,
				Bw:        res.Bw,
				StartsAt:  timestamppb.New(res.StartsAt),
				StopsAt:   timestamppb.New(res.StopsAt),
				Ak:        res.Ak,
			})
		}
		return nil
	})

	return &connect.Response[hummingbird.FetchReservationsResponse]{
		Msg: &hummingbird.FetchReservationsResponse{
			Reservations: resp,
		},
	}, nil
}

func (s *Service) Info(context.Context, *connect.Request[hummingbird.MarketplaceInfoRequest]) (*connect.Response[hummingbird.MarketplaceInfoResponse], error) {
	fmt.Println("Info")
	return &connect.Response[hummingbird.MarketplaceInfoResponse]{
		Msg: &hummingbird.MarketplaceInfoResponse{
			ApiMajorVersion: 0,
			ApiMinorVersion: 1,
			Currency:        "CHF",
		},
	}, nil
}

func (s *Service) PublishAsset(ctx context.Context, req *connect.Request[hummingbird.PublishAssetRequest]) (*connect.Response[hummingbird.PublishAssetResponse], error) {
	fmt.Println("PublishAsset")
	user := ctx.Value("user").(*ASUser)
	ia := user.IA
	asset := &Asset{
		IA:              ia,
		Bandwidth:       req.Msg.Bandwidth,
		BandwidthMin:    req.Msg.BandwidthMin,
		StartAt:         req.Msg.StartAt.AsTime().Truncate(time.Second),
		StopsAt:         req.Msg.StopsAt.AsTime().Truncate(time.Second),
		Price:           req.Msg.Price,
		TimeGranularity: req.Msg.TimeGranularity,
		TimeMinDuration: req.Msg.TimeMinDuration,
		IfIdIngress:     req.Msg.IfIdIngress,
		IfIdEgress:      req.Msg.IfIdEgress,
		state:           Listed,
	}
	assetID := s.currentAssetID.Add(1)
	s.globalAssetsModOp(func(m map[uint64]*Asset) error {
		m[assetID] = asset
		return nil
	})
	return &connect.Response[hummingbird.PublishAssetResponse]{
		Msg: &hummingbird.PublishAssetResponse{
			AssetId: assetID,
		},
	}, nil
}

func (s *Service) RedeemAsset(ctx context.Context, req *connect.Request[hummingbird.RedeemAssetRequest]) (*connect.Response[hummingbird.RedeemAssetResponse], error) {
	fmt.Println("RedeemAsset")
	user := ctx.Value("user").(*User)
	var bw uint64
	var ingressID uint32
	var egressID uint32
	var startsAt time.Time
	var stopsAt time.Time
	var ia addr.IA
	isInterfacePair := false
	if req.Msg.IfPairAssetId != nil {
		isInterfacePair = true
		err := s.assetOp(*req.Msg.IfPairAssetId, func(pairAsset *Asset) error {
			if pairAsset.Owner != user.Username {
				return serrors.New("user is not owner of the asset")
			}
			if pairAsset.state != Bought {
				return serrors.New("asset already redeemed")
			}
			if pairAsset.IfIdIngress == nil {
				return serrors.New("pair asset requires ingress interface")
			}
			if pairAsset.IfIdEgress == nil {
				return serrors.New("pair asset requires egress interface")
			}
			bw = pairAsset.Bandwidth
			ingressID = *pairAsset.IfIdIngress
			egressID = *pairAsset.IfIdEgress
			startsAt = pairAsset.StartAt
			stopsAt = pairAsset.StopsAt
			ia = pairAsset.IA
			pairAsset.state = BeingRedeemed
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		if req.Msg.IngressAssetId == req.Msg.EgressAssetId {
			return nil, serrors.New("Cannot use same asset ID for ingress and egress asset")
		}
		var err error
		verifyAssets := func(ingressAsset *Asset, egressAsset *Asset) error {
			if ingressAsset.Owner != user.Username {
				return serrors.New("user is not owner of the asset")
			}
			if ingressAsset.state != Bought {
				return serrors.New("ingress asset already redeemed")
			}
			if egressAsset.Owner != user.Username {
				return serrors.New("user is not owner of the asset")
			}
			if egressAsset.state != Bought {
				return serrors.New("egress asset already redeemed")
			}
			if ingressAsset.IA != egressAsset.IA {
				return serrors.New("ingress and egress asset have to belong to same IA")
			}
			if ingressAsset.IfIdIngress == nil {
				return serrors.New("ingress asset requires ingress interface")
			}
			if egressAsset.IfIdEgress == nil {
				return serrors.New("egress asset requires egress interface")
			}
			bw = min(ingressAsset.Bandwidth, egressAsset.Bandwidth)
			ingressID = *ingressAsset.IfIdIngress
			egressID = *egressAsset.IfIdEgress
			ia = ingressAsset.IA
			if ingressAsset.StartAt.Before(egressAsset.StartAt) {
				startsAt = egressAsset.StartAt
			} else {
				startsAt = ingressAsset.StartAt
			}
			if ingressAsset.StopsAt.Before(egressAsset.StopsAt) {
				stopsAt = ingressAsset.StopsAt
			} else {
				stopsAt = egressAsset.StopsAt
			}
			if stopsAt.Before(startsAt) {
				return serrors.New("stopsAt before startsAt")
			}
			ingressAsset.state = BeingRedeemed
			egressAsset.state = BeingRedeemed
			return nil
		}
		if req.Msg.IngressAssetId < req.Msg.EgressAssetId {
			err = s.assetOp(req.Msg.IngressAssetId, func(ingressAsset *Asset) error {
				return s.assetOp(req.Msg.EgressAssetId, func(egressAsset *Asset) error {
					return verifyAssets(ingressAsset, egressAsset)
				})
			})
		} else {
			err = s.assetOp(req.Msg.EgressAssetId, func(egressAsset *Asset) error {
				return s.assetOp(req.Msg.IngressAssetId, func(ingressAsset *Asset) error {
					return verifyAssets(ingressAsset, egressAsset)
				})
			})
		}

		if err != nil {
			return nil, err
		}
	}
	undoRedemption := func() {
		if isInterfacePair {
			s.assetOp(*req.Msg.IfPairAssetId, func(a *Asset) error {
				a.state = Bought
				return nil
			})
		} else {
			if req.Msg.IngressAssetId < req.Msg.EgressAssetId {
				s.assetOp(req.Msg.IngressAssetId, func(ingressAsset *Asset) error {
					return s.assetOp(req.Msg.EgressAssetId, func(egressAsset *Asset) error {
						ingressAsset.state = Bought
						egressAsset.state = Bought
						return nil
					})
				})
			} else {
				s.assetOp(req.Msg.EgressAssetId, func(egressAsset *Asset) error {
					return s.assetOp(req.Msg.IngressAssetId, func(ingressAsset *Asset) error {
						ingressAsset.state = Bought
						egressAsset.state = Bought
						return nil
					})
				})
			}

		}
	}
	peer, found := s.redemptionServerPeers[ia]
	if !found {
		undoRedemption()
		return nil, serrors.New("peer not found", "key", ia)
	}
	respCh := peer.Send(&hummingbird.RedeemAssetFromASRequest{
		Bw:        bw,
		IngressId: ingressID,
		EgressId:  egressID,
		StartsAt:  timestamppb.New(startsAt),
		StopsAt:   timestamppb.New(stopsAt),
	})
	select {
	case resp := <-respCh:
		res := &Reservation{
			ResId:     resp.ResInfo.ResId,
			Ia:        ia,
			IngressId: ingressID,
			EgressId:  egressID,
			Bw:        bw,
			StartsAt:  startsAt,
			StopsAt:   stopsAt,
		}
		s.reservationOp(user, func(r *[]*Reservation) error {
			*r = append(*r, res)
			return nil
		})
		s.globalAssetsModOp(func(m map[uint64]*Asset) error {
			if isInterfacePair {
				delete(m, *req.Msg.IfPairAssetId)
			} else {
				delete(m, req.Msg.IngressAssetId)
				delete(m, req.Msg.EgressAssetId)
			}
			return nil
		})
		return &connect.Response[hummingbird.RedeemAssetResponse]{
			Msg: &hummingbird.RedeemAssetResponse{
				Ak:                  resp.Ak,
				ResId:               resp.ResInfo.ResId,
				BwRounded:           resp.ResInfo.BwRounded,
				BwDataplaneEncoding: resp.ResInfo.BwDataplaneEncoding,
			},
		}, nil
	case <-time.After(10 * time.Second):
		undoRedemption()
		return nil, serrors.New("timeout")
	}
}

func (s *Service) SearchAssets(ctx context.Context, req *connect.Request[hummingbird.SearchAssetsRequest]) (*connect.Response[hummingbird.SearchAssetsResponse], error) {
	fmt.Println("SearchAssets")
	user := ctx.Value("user").(*User)
	repAssets := make([]*hummingbird.Asset, 0, 1)
	s.assetMtx.RLock()
	defer s.assetMtx.RUnlock()
	for id, asset := range s.assets {
		if req.Msg.Owned {
			if asset.Owner != user.Username {
				continue
			}
		} else if asset.Owner != "" {
			continue
		}
		if req.Msg.Ia != nil && *req.Msg.Ia != uint64(asset.IA) {
			continue
		}
		if req.Msg.AssetType != nil {
			if *req.Msg.AssetType == hummingbird.AssetType_Interface_Pair && (asset.IfIdIngress == nil || asset.IfIdEgress == nil) {
				continue
			}
			if *req.Msg.AssetType == hummingbird.AssetType_Ingress && (asset.IfIdIngress == nil || asset.IfIdEgress != nil) {
				continue
			}
			if *req.Msg.AssetType == hummingbird.AssetType_Egress && (asset.IfIdEgress == nil || asset.IfIdIngress != nil) {
				continue
			}
		}
		if req.Msg.MinRequiredBw != nil && asset.Bandwidth < *req.Msg.MinRequiredBw {
			continue
		}
		if req.Msg.Price != nil && asset.Price > *req.Msg.Price {
			continue
		}
		if req.Msg.StartsAtLatest != nil && asset.StartAt.After(req.Msg.StartsAtLatest.AsTime()) {
			continue
		}
		if req.Msg.StopsAtEarliest != nil && asset.StopsAt.Before(req.Msg.StopsAtEarliest.AsTime()) {
			continue
		}
		repAsset := &hummingbird.Asset{
			AssetId:         id,
			Ia:              uint64(asset.IA),
			Bw:              asset.Bandwidth,
			StartsAt:        timestamppb.New(asset.StartAt),
			StopsAt:         timestamppb.New(asset.StopsAt),
			Price:           asset.Price,
			TimeGranularity: asset.TimeGranularity,
		}
		if asset.IfIdIngress != nil && asset.IfIdEgress != nil {
			repAsset.AssetType = hummingbird.AssetType_Interface_Pair
			repAsset.IfIdIngress = asset.IfIdIngress
			repAsset.IfIdEgress = asset.IfIdEgress
		} else if asset.IfIdIngress != nil {
			repAsset.AssetType = hummingbird.AssetType_Ingress
			repAsset.IfIdIngress = asset.IfIdIngress
		} else if asset.IfIdEgress != nil {
			repAsset.AssetType = hummingbird.AssetType_Egress
			repAsset.IfIdEgress = asset.IfIdEgress
		}
		repAssets = append(repAssets, repAsset)
	}

	return &connect.Response[hummingbird.SearchAssetsResponse]{
		Msg: &hummingbird.SearchAssetsResponse{
			Owned:  req.Msg.Owned,
			Assets: repAssets,
		},
	}, nil
}
