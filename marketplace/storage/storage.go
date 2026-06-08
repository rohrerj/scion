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

package storage

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	marketplacedb "github.com/scionproto/scion/marketplace/db"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/storage/db"
)

type DBConfig struct {
	config.NoDefaulter
	Connection       string `toml:"connection,omitempty"`
	MaxOpenReadConns int    `toml:"max_open_read_conns,omitempty"`
	MaxIdleReadConns int    `toml:"max_idle_read_conns,omitempty"`
	allowEmptyConn   bool
}

type MarketplaceStorage struct {
	db marketplacedb.MarketplaceDB
}

func NewStorage(c DBConfig) (*MarketplaceStorage, error) {
	db, err := marketplacedb.New(c.Connection, &db.SqliteConfig{
		MaxOpenReadConns: c.MaxOpenReadConns,
		MaxIdleReadConns: c.MaxIdleReadConns,
	})
	if err != nil {
		return nil, err
	}
	return &MarketplaceStorage{
		db: db,
	}, nil
}

func (s *MarketplaceStorage) Search(ctx context.Context, params *marketplacedb.AssetQuery) ([]*marketplacedb.DBAsset, error) {
	return s.db.Search(ctx, params)
}

func (s *MarketplaceStorage) PublishAsset(ctx context.Context, a *marketplacedb.DBAsset) (int64, error) {
	return s.db.InsertAsset(ctx, a)
}

func (s *MarketplaceStorage) GetUser(ctx context.Context, name string) (*marketplacedb.DBUser, error) {
	return s.db.GetUser(ctx, name)
}

func (s *MarketplaceStorage) CreateUser(ctx context.Context, user *marketplacedb.DBUser) (int64, error) {
	return s.db.CreateUser(ctx, user)
}

func (s *MarketplaceStorage) CreateASUser(ctx context.Context, user *marketplacedb.DBASUser) (int64, error) {
	return s.db.CreateASUser(ctx, user)
}

func totalPrice(price uint64, bw uint64, startsAt time.Time, stopsAt time.Time) int64 {
	splitDuration := uint64(stopsAt.Sub(startsAt).Seconds())
	return int64(price * splitDuration * bw)
}

func (s *MarketplaceStorage) BuyAssets(ctx context.Context, user string, assets []*hummingbird.BuyAsset, maxPrice uint64) ([]int64, int64, error) {
	uniqueCheck := make(map[string]bool)
	for _, asset := range assets {
		if uniqueCheck[asset.AssetId] {
			return nil, 0, serrors.New("Only a single split per asset per buy request allowed")
		}
		if asset.StopsAtExactly.AsTime().Before(asset.StartsAtExactly.AsTime()) {
			return nil, 0, serrors.New("End of validity must come after start of validity")
		}
		uniqueCheck[asset.AssetId] = true
	}
	tx, err := s.db.BeginTransaction(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, 0, err
	}
	boughtAssets := make([]int64, 0, 1)
	costAcc := int64(0)
	for _, asset := range assets {
		assetId, err := strconv.ParseInt(asset.AssetId, 10, 64)
		if err != nil {
			return nil, 0, serrors.Join(err, tx.Rollback())
		}
		dbAsset, err := tx.AssetByID(ctx, assetId)
		if err != nil {
			return nil, 0, serrors.Join(err, tx.Rollback())
		}
		split, err := SplitAsset(dbAsset, []RequestedSplit{
			{
				ExactFrom:      asset.StartsAtExactly.AsTime(),
				ExactTo:        asset.StopsAtExactly.AsTime(),
				ExactBandwidth: asset.BwExact,
			},
		})
		if err != nil {
			return nil, 0, serrors.Join(err, tx.Rollback())
		}
		for _, segment := range split.Bought {
			newAsset := &marketplacedb.DBAsset{
				Owner: sql.NullString{
					String: user,
					Valid:  true,
				},
				IA:              dbAsset.IA,
				BandwidthMin:    dbAsset.BandwidthMin,
				TimeGranularity: dbAsset.TimeGranularity,
				TimeMinDuration: dbAsset.TimeMinDuration,
				IfIdIngress:     dbAsset.IfIdIngress,
				IfIdEgress:      dbAsset.IfIdEgress,
				Bandwidth:       segment.Bandwidth,
				StartAt:         segment.StartAt,
				StopsAt:         segment.StopAt,
			}
			id, err := tx.InsertAsset(ctx, newAsset)
			if err != nil {
				return nil, 0, serrors.Join(err, tx.Rollback())
			}
			costAcc += totalPrice(dbAsset.Price, segment.Bandwidth, segment.StartAt, segment.StopAt)
			boughtAssets = append(boughtAssets, id)
		}
		for _, segment := range split.Unused {
			newAsset := &marketplacedb.DBAsset{
				IA:              dbAsset.IA,
				BandwidthMin:    dbAsset.BandwidthMin,
				TimeGranularity: dbAsset.TimeGranularity,
				TimeMinDuration: dbAsset.TimeMinDuration,
				IfIdIngress:     dbAsset.IfIdIngress,
				IfIdEgress:      dbAsset.IfIdEgress,
				Bandwidth:       segment.Bandwidth,
				StartAt:         segment.StartAt,
				StopsAt:         segment.StopAt,
				Price:           dbAsset.Price,
			}
			_, err := tx.InsertAsset(ctx, newAsset)
			if err != nil {
				return nil, 0, serrors.Join(err, tx.Rollback())
			}
		}
		err = tx.RemoveAsset(ctx, int64(dbAsset.ID))
		if err != nil {
			return nil, 0, serrors.Join(err, tx.Rollback())
		}
	}
	if uint64(costAcc) > maxPrice {
		return nil, 0, serrors.Join(serrors.New("cost higher than max price"), tx.Rollback())
	}
	_, err = tx.UpdateMoney(ctx, user, -costAcc)
	if err != nil {
		return nil, 0, serrors.Join(err, tx.Rollback())
	}
	err = tx.Commit()
	if err != nil {
		return nil, 0, serrors.Join(err, tx.Rollback())
	}
	return boughtAssets, costAcc, nil
}

func (s *MarketplaceStorage) DepositMoneyAndGet(ctx context.Context, name string, amount int64) (*marketplacedb.DBUser, error) {
	tx, err := s.db.BeginTransaction(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, err
	}
	_, err = tx.UpdateMoney(ctx, name, amount)
	if err != nil {
		return nil, serrors.Join(err, tx.Rollback())
	}
	user, err := tx.GetUser(ctx, name)
	if err != nil {
		return nil, serrors.Join(err, tx.Rollback())
	}
	err = tx.Commit()
	if err != nil {
		return nil, serrors.Join(err, tx.Rollback())
	}
	return user, nil
}
