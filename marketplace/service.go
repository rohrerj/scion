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
	redeemed        bool
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

func (s *Service) BuyAssets(ctx context.Context, req *connect.Request[hummingbird.BuyAssetsRequest]) (*connect.Response[hummingbird.BuyAssetsResponse], error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	fmt.Println("BuyAssets")
	user := ctx.Value("user").(*User)
	boughtAssets := make([]*hummingbird.BoughtAsset, 0, 1)
	accCost := uint64(0)
	for _, reqAsset := range req.Msg.Assets {
		err := s.assetOp(reqAsset.AssetId, func(a *Asset) error {
			a.Owner = user.Username
			accCost += a.Price
			boughtAssets = append(boughtAssets, &hummingbird.BoughtAsset{
				AssetId: reqAsset.AssetId,
			})
			return nil
		})
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, serrors.New("Asset not found"))
		}
		if accCost > req.Msg.MaxPrice {
			break
		}
	}
	if accCost > req.Msg.MaxPrice {
		//undo purchase
		for _, asset := range boughtAssets {
			s.assetOp(asset.AssetId, func(a *Asset) error {
				a.Owner = ""
				return nil
			})
		}
		return nil, connect.NewError(connect.CodeFailedPrecondition, serrors.New("Insufficient credit"))
	}
	return &connect.Response[hummingbird.BuyAssetsResponse]{
		Msg: &hummingbird.BuyAssetsResponse{
			Assets: boughtAssets,
			Cost:   accCost,
		},
	}, nil
}

func (s *Service) FetchReservations(ctx context.Context, req *connect.Request[hummingbird.FetchReservationsRequest]) (*connect.Response[hummingbird.FetchReservationsResponse], error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	user := ctx.Value("user").(*User)
	resp := make([]*hummingbird.Reservation, 0, 1)
	s.reservationOp(user, func(r *[]*Reservation) error {
		fmt.Println("R", len(*r))
		for _, res := range *r {
			if req.Msg.Ia != nil && uint64(res.Ia) != *req.Msg.Ia {
				fmt.Println(0)
				continue
			}
			if req.Msg.StartsAt != nil && res.StartsAt.Before(req.Msg.StartsAt.AsTime()) {
				fmt.Println(1)
				continue
			}
			if req.Msg.StopsAt != nil && res.StopsAt.After(req.Msg.StopsAt.AsTime()) {
				fmt.Println(2)
				continue
			}
			if req.Msg.Bw != nil && res.Bw < *req.Msg.Bw {
				fmt.Println(3)
				continue
			}
			if req.Msg.IngressId != nil && res.IngressId != *req.Msg.IngressId {
				fmt.Println(4)
				continue
			}
			if req.Msg.EgressId != nil && res.EgressId != *req.Msg.EgressId {
				fmt.Println(5)
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
			ApiMajorVersion: 1,
			ApiMinorVersion: 2,
			Currency:        "CHF",
		},
	}, nil
}

func (s *Service) PublishAsset(ctx context.Context, req *connect.Request[hummingbird.PublishAssetRequest]) (*connect.Response[hummingbird.PublishAssetResponse], error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	fmt.Println("PublishAsset")
	user := ctx.Value("user").(*ASUser)
	ia := user.IA
	asset := &Asset{
		IA:              ia,
		Bandwidth:       req.Msg.Bandwidth,
		BandwidthMin:    req.Msg.BandwidthMin,
		StartAt:         req.Msg.StartAt.AsTime(),
		StopsAt:         req.Msg.StopsAt.AsTime(),
		Price:           req.Msg.Price,
		TimeGranularity: req.Msg.TimeGranularity,
		TimeMinDuration: req.Msg.TimeMinDuration,
		IfIdIngress:     req.Msg.IfIdIngress,
		IfIdEgress:      req.Msg.IfIdEgress,
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
	s.mtx.Lock()
	defer s.mtx.Unlock()
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
			if pairAsset.redeemed {
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
			pairAsset.redeemed = true
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		if req.Msg.IngressAssetId == req.Msg.EgressAssetId {
			return nil, serrors.New("Cannot use same asset ID for ingress and egress asset")
		}
		err := s.assetOp(req.Msg.IngressAssetId, func(ingressAsset *Asset) error {
			return s.assetOp(req.Msg.EgressAssetId, func(egressAsset *Asset) error {
				if ingressAsset.Owner != user.Username {
					return serrors.New("user is not owner of the asset")
				}
				if ingressAsset.redeemed {
					return serrors.New("ingress asset already redeemed")
				}
				if egressAsset.Owner != user.Username {
					return serrors.New("user is not owner of the asset")
				}
				if egressAsset.redeemed {
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
				}
				if ingressAsset.StopsAt.Before(egressAsset.StopsAt) {
					stopsAt = ingressAsset.StopsAt
				}
				if stopsAt.Before(startsAt) {
					return serrors.New("stopsAt before startsAt")
				}
				ingressAsset.redeemed = true
				egressAsset.redeemed = true
				return nil
			})
		})
		if err != nil {
			return nil, err
		}
	}
	undoRedemption := func() {
		if isInterfacePair {
			s.assetOp(*req.Msg.IfPairAssetId, func(a *Asset) error {
				a.redeemed = false
				return nil
			})
		} else {
			s.assetOp(req.Msg.IngressAssetId, func(ingressAsset *Asset) error {
				return s.assetOp(req.Msg.EgressAssetId, func(egressAsset *Asset) error {
					ingressAsset.redeemed = false
					egressAsset.redeemed = false
					return nil
				})
			})
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
	s.mtx.Lock()
	defer s.mtx.Unlock()
	fmt.Println("SearchAssets")
	user := ctx.Value("user").(*User)
	repAssets := make([]*hummingbird.Asset, 0, 1)
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
			if *req.Msg.AssetType == hummingbird.AssetType_Ingress && asset.IfIdIngress == nil {
				continue
			}
			if *req.Msg.AssetType == hummingbird.AssetType_Egress && asset.IfIdEgress == nil {
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
