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
)

type Asset struct {
	Owner           string
	IA              addr.IA
	Bandwidth       uint64
	BandwidthMin    uint64
	StartAt         uint64
	StopsAt         uint64
	Price           uint64
	TimeGranularity uint64
	TimeMinDuration uint64
	BwGranularity   uint64
	IfIdIngress     *uint32
	IfIdEgress      *uint32
}

type Service struct {
	redemptionServerPeers map[addr.IA]*RedemptionServerPeer
	assets                map[uint64]*Asset
	currentAssetID        uint64
	mtx                   sync.Mutex
}

func NewService() *Service {
	return &Service{
		redemptionServerPeers: make(map[addr.IA]*RedemptionServerPeer),
		assets:                make(map[uint64]*Asset),
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

func (s *Service) FetchReservations(context.Context, *connect.Request[hummingbird.FetchReservationsRequest]) (*connect.Response[hummingbird.FetchReservationsResponse], error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return nil, nil
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
		StartAt:         req.Msg.StartAt,
		StopsAt:         req.Msg.StopsAt,
		Price:           req.Msg.Price,
		TimeGranularity: req.Msg.TimeGranularity,
		TimeMinDuration: req.Msg.TimeMinDuration,
		BwGranularity:   req.Msg.BwGranularity,
		IfIdIngress:     req.Msg.IfIdIngress,
		IfIdEgress:      req.Msg.IfIdEgress,
	}
	s.currentAssetID++
	return &connect.Response[hummingbird.PublishAssetResponse]{
		Msg: &hummingbird.PublishAssetResponse{},
	}, nil
}

func (s *Service) RedeemAsset(ctx context.Context, req *connect.Request[hummingbird.RedeemAssetRequest]) (*connect.Response[hummingbird.RedeemAssetResponse], error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	fmt.Println("RedeemAsset")
	user := ctx.Value("user").(string)
	ingressAsset, found := s.assets[req.Msg.IngressAssetId]
	if !found {
		return nil, serrors.New("asset not found")
	}
	if ingressAsset.Owner != user {
		return nil, serrors.New("user is not owner of the asset")
	}
	peer1, found := s.redemptionServerPeers[ingressAsset.IA]
	if !found {
		return nil, serrors.New("peer not found", "key", ingressAsset.IA)
	}
	respCh := peer1.Send(&hummingbird.RedeemAssetFromASRequest{
		Bw: ingressAsset.Bandwidth,
		// other fields omitted
	})
	select {
	case resp := <-respCh:
		fmt.Println("got out of receive channel")
		return &connect.Response[hummingbird.RedeemAssetResponse]{
			Msg: &hummingbird.RedeemAssetResponse{
				Ak:    resp.Ak,
				ResId: "my-res-id",
			},
		}, nil
	case <-time.After(2 * time.Second):
		return nil, serrors.New("timeout")
	}
}

func (s *Service) SearchAssets(ctx context.Context, req *connect.Request[hummingbird.SearchAssetsRequest]) (*connect.Response[hummingbird.SearchAssetsResponse], error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	fmt.Println("SearchAssets")
	user := ctx.Value("user").(string)
	repAssets := make([]*hummingbird.Asset, 0, len(s.assets))
	if req.Msg.Owned {
		for id, asset := range s.assets {
			if req.Msg.Ia != nil && *req.Msg.Ia != uint64(asset.IA) {
				continue
			}
			if asset.Owner == user {
				repAssets = append(repAssets, &hummingbird.Asset{
					AssetId:  id,
					Ia:       uint64(asset.IA),
					Bw:       asset.Bandwidth,
					StartsAt: asset.StartAt,
					StopsAt:  asset.StopsAt,
					// other fields omitted
				})
			}
		}
	} else {
		for id, asset := range s.assets {
			if req.Msg.Ia != nil && *req.Msg.Ia != uint64(asset.IA) {
				continue
			}
			if asset.Owner == "" {
				repAssets = append(repAssets, &hummingbird.Asset{
					AssetId:  id,
					Ia:       uint64(asset.IA),
					Bw:       asset.Bandwidth,
					StartsAt: asset.StartAt,
					StopsAt:  asset.StopsAt,
					// other fields omitted
				})
			}

		}
	}

	return &connect.Response[hummingbird.SearchAssetsResponse]{
		Msg: &hummingbird.SearchAssetsResponse{
			Owned:  false,
			Assets: repAssets,
		},
	}, nil
}
