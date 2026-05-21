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
	currentAssetID        uint64
	reservations          map[string][]*Reservation
	mtx                   sync.Mutex
}

func NewService() *Service {
	return &Service{
		redemptionServerPeers: make(map[addr.IA]*RedemptionServerPeer),
		assets:                make(map[uint64]*Asset),
		reservations:          make(map[string][]*Reservation),
		currentAssetID:        1,
	}
}

func (s *Service) BuyAssets(ctx context.Context, req *connect.Request[hummingbird.BuyAssetsRequest]) (*connect.Response[hummingbird.BuyAssetsResponse], error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	fmt.Println("BuyAssets")
	user := ctx.Value("user").(string)
	boughtAssets := make([]*hummingbird.BoughtAsset, 0, 1)
	for _, reqAsset := range req.Msg.Assets {
		asset, found := s.assets[reqAsset.AssetId]
		if !found {
			return nil, serrors.New("asset not found")
		}
		asset.Owner = user
		boughtAssets = append(boughtAssets, &hummingbird.BoughtAsset{
			AssetId: reqAsset.AssetId,
		})
	}
	return &connect.Response[hummingbird.BuyAssetsResponse]{
		Msg: &hummingbird.BuyAssetsResponse{
			Assets: boughtAssets,
		},
	}, nil
}

func (s *Service) FetchReservations(ctx context.Context, req *connect.Request[hummingbird.FetchReservationsRequest]) (*connect.Response[hummingbird.FetchReservationsResponse], error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	user := ctx.Value("user").(string)
	allReservations := s.reservations[user]
	resp := make([]*hummingbird.Reservation, 0, 1)
	for _, res := range allReservations {
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
	user := ctx.Value("user").(string)
	ia, err := addr.ParseIA(user)
	if err != nil {
		return nil, err
	}

	s.assets[s.currentAssetID] = &Asset{
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
	resp := &hummingbird.PublishAssetResponse{
		AssetId: s.currentAssetID,
	}
	s.currentAssetID++
	return &connect.Response[hummingbird.PublishAssetResponse]{
		Msg: resp,
	}, nil
}

func (s *Service) RedeemAsset(ctx context.Context, req *connect.Request[hummingbird.RedeemAssetRequest]) (*connect.Response[hummingbird.RedeemAssetResponse], error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	fmt.Println("RedeemAsset")
	user := ctx.Value("user").(string)
	var bw uint64
	var ingressID uint32
	var egressID uint32
	var startsAt time.Time
	var stopsAt time.Time
	var ia addr.IA
	if req.Msg.IfPairAssetId != nil {
		pairAsset, found := s.assets[*req.Msg.IfPairAssetId]
		if !found {
			return nil, serrors.New("asset not found")
		}
		if pairAsset.Owner != user {
			return nil, serrors.New("user is not owner of the asset")
		}
		if pairAsset.IfIdIngress == nil {
			return nil, serrors.New("pair asset requires ingress interface")
		}
		if pairAsset.IfIdEgress == nil {
			return nil, serrors.New("pair asset requires egress interface")
		}
		bw = pairAsset.Bandwidth
		ingressID = *pairAsset.IfIdIngress
		egressID = *pairAsset.IfIdEgress
		startsAt = pairAsset.StartAt
		stopsAt = pairAsset.StopsAt
		ia = pairAsset.IA
	} else {
		ingressAsset, found := s.assets[req.Msg.IngressAssetId]
		if !found {
			return nil, serrors.New("asset not found")
		}
		if ingressAsset.Owner != user {
			return nil, serrors.New("user is not owner of the asset")
		}
		egressAsset, found := s.assets[req.Msg.EgressAssetId]
		if !found {
			return nil, serrors.New("asset not found")
		}
		if egressAsset.Owner != user {
			return nil, serrors.New("user is not owner of the asset")
		}
		if ingressAsset.IA != egressAsset.IA {
			return nil, serrors.New("ingress and egress asset have to belong to same IA")
		}
		if ingressAsset.IfIdIngress == nil {
			return nil, serrors.New("ingress asset requires ingress interface")
		}
		if egressAsset.IfIdEgress == nil {
			return nil, serrors.New("egress asset requires egress interface")
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
	}
	if stopsAt.Before(startsAt) {
		return nil, serrors.New("egress asset requires egress interface")
	}
	peer, found := s.redemptionServerPeers[ia]
	if !found {
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
		userReservations, found := s.reservations[user]
		if !found {
			userReservations = []*Reservation{}
			s.reservations[user] = userReservations
		}
		userReservations = append(userReservations, &Reservation{
			ResId:     resp.ResInfo.ResId,
			Ia:        ia,
			IngressId: ingressID,
			EgressId:  egressID,
			Bw:        bw,
			StartsAt:  startsAt,
			StopsAt:   stopsAt,
		})
		return &connect.Response[hummingbird.RedeemAssetResponse]{
			Msg: &hummingbird.RedeemAssetResponse{
				Ak:                  resp.Ak,
				ResId:               resp.ResInfo.ResId,
				BwRounded:           resp.ResInfo.BwRounded,
				BwDataplaneEncoding: resp.ResInfo.BwDataplaneEncoding,
			},
		}, nil
	case <-time.After(5 * time.Second):
		return nil, serrors.New("timeout")
	}
}

func (s *Service) SearchAssets(ctx context.Context, req *connect.Request[hummingbird.SearchAssetsRequest]) (*connect.Response[hummingbird.SearchAssetsResponse], error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	fmt.Println("SearchAssets")
	user := ctx.Value("user").(string)
	repAssets := make([]*hummingbird.Asset, 0, 1)
	for id, asset := range s.assets {
		if req.Msg.Owned {
			if asset.Owner != user {
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
