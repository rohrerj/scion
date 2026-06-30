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
	"math"
	"strconv"
	"time"

	marketplacedb "github.com/scionproto/scion/marketplace/db"
	"github.com/scionproto/scion/pkg/addr"
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
	db                      marketplacedb.MarketplaceDB
	transactionFeeRelative  float32
	transactionFeeAbsolute  uint64
	splitCombineFeeAbsolute uint64
	delegationHourlyFee     uint64
}

func NewStorage(c DBConfig, transactionFeeRelative float32, transactionFeeAbsolute uint64, splitCombineFeeAbsolute uint64, delegationHourlyFee uint64) (
	*MarketplaceStorage, error) {
	db, err := marketplacedb.New(c.Connection, &db.SqliteConfig{
		MaxOpenReadConns: c.MaxOpenReadConns,
		MaxIdleReadConns: c.MaxIdleReadConns,
	})
	if err != nil {
		return nil, err
	}
	return &MarketplaceStorage{
		db:                      db,
		transactionFeeRelative:  transactionFeeRelative,
		transactionFeeAbsolute:  transactionFeeAbsolute,
		splitCombineFeeAbsolute: splitCombineFeeAbsolute,
		delegationHourlyFee:     delegationHourlyFee,
	}, nil
}

func (s *MarketplaceStorage) Search(ctx context.Context, params *marketplacedb.AssetQuery) ([]*marketplacedb.DBAsset, error) {
	return s.db.Search(ctx, params)
}

func (s *MarketplaceStorage) FetchReservations(ctx context.Context, params *marketplacedb.ReservationQuery) ([]*marketplacedb.DBReservation, error) {
	return s.db.FetchReservations(ctx, params)
}

func (s *MarketplaceStorage) PublishAsset(ctx context.Context, a *marketplacedb.DBAsset) (int64, error) {
	err := validateAsset(a)
	if err != nil {
		return 0, err
	}
	return s.db.InsertAsset(ctx, a)
}
func (s *MarketplaceStorage) UpdateListedAsset(ctx context.Context, a *marketplacedb.DBAsset) (int64, error) {
	err := validateAsset(a)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTransaction(ctx, &sql.TxOptions{})
	if err != nil {
		return 0, err
	}
	x, err := tx.DeleteListedAsset(ctx, a.IA, a.ID)
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	if x != 1 {
		return 0, serrors.Join(serrors.New("no modifiable asset with that ID found"), tx.Rollback())
	}
	newId, err := tx.InsertAsset(ctx, a)
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	err = tx.Commit()
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	return newId, nil
}
func (s *MarketplaceStorage) DeleteListedAsset(ctx context.Context, ia addr.IA, assetID int64) (int64, error) {
	return s.db.DeleteListedAsset(ctx, ia, assetID)
}

func (s *MarketplaceStorage) GetUser(ctx context.Context, id int64) (*marketplacedb.DBUser, error) {
	return s.db.GetUser(ctx, id)
}

func (s *MarketplaceStorage) GetASUser(ctx context.Context, ia addr.IA) (*marketplacedb.DBASUser, error) {
	return s.db.GetASUser(ctx, ia)
}

func (s *MarketplaceStorage) SetASAuthenticationToken(ctx context.Context, ia addr.IA, auth string) (int64, error) {
	return s.db.SetASAuthenticationToken(ctx, ia, auth)
}

func (s *MarketplaceStorage) GetUserByName(ctx context.Context, name string) (*marketplacedb.DBUser, error) {
	return s.db.GetUserByName(ctx, name)
}

func (s *MarketplaceStorage) CreateUser(ctx context.Context, user *marketplacedb.DBUser) (int64, error) {
	return s.db.CreateUser(ctx, user)
}

func (s *MarketplaceStorage) CreateASUser(ctx context.Context, user *marketplacedb.DBASUser) (int64, error) {
	return s.db.CreateASUser(ctx, user)
}
func ceilDuration(base time.Duration, multiple time.Duration) time.Duration {
	truncated := base.Truncate(multiple)
	if truncated == base {
		return base
	}
	return truncated + multiple
}
func (s *MarketplaceStorage) CreateOrUpdateRedemptionDelegations(ctx context.Context, r *marketplacedb.RedemptionDelegation) (int64, error) {
	tx, err := s.db.BeginTransaction(ctx, &sql.TxOptions{})
	if err != nil {
		return 0, err
	}
	var paidUntil time.Time
	dbDelegation, err := tx.FindRedemptionDelegation(ctx, r.IA)
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	if dbDelegation == nil {
		paidUntil = time.Now()
	} else {
		paidUntil = dbDelegation.PaidUntil
	}
	if s.delegationHourlyFee == 0 {
		// service is free, just update paidUntil accordingly to ensure database constraints do not complain
		if r.Expiration.After(paidUntil) {
			r.PaidUntil = r.Expiration
		}
	} else {
		// service requires payment
		if r.Expiration.After(paidUntil) {
			// expiration is later than currently paid period, so requires further payment
			paymentDuration := ceilDuration(r.Expiration.Sub(paidUntil), time.Hour)
			numHours := uint64(paymentDuration / time.Hour)
			_, err = tx.UpdateASMoney(ctx, r.IA, -int64(numHours*s.delegationHourlyFee))
			if err != nil {
				return 0, serrors.Join(err, tx.Rollback())
			}
			r.PaidUntil = paidUntil.Add(paymentDuration)
		} else {
			// user updated expiration but this is still within the period he already paid, so skip billing.
			r.PaidUntil = paidUntil
		}
	}
	id, err := tx.CreateOrUpdateRedemptionDelegations(ctx, r)
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	err = tx.Commit()
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	return id, nil
}
func (s *MarketplaceStorage) FindRedemptionDelegations(ctx context.Context) ([]*marketplacedb.RedemptionDelegation, error) {
	return s.db.FindRedemptionDelegations(ctx)
}

func mulInt64(a, b int64) (int64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	if a == math.MinInt64 && b == -1 {
		return 0, false
	}
	if b == math.MinInt64 && a == -1 {
		return 0, false
	}
	if a > math.MaxInt64/b || a < math.MinInt64/b {
		return 0, false
	}
	return a * b, true
}

func addInt64(a, b int64) (int64, bool) {
	if (b > 0 && a > math.MaxInt64-b) ||
		(b < 0 && a < math.MinInt64-b) {
		return 0, false // overflow
	}
	return a + b, true
}

func (s *MarketplaceStorage) totalPrice(price uint32, bw uint32, startsAt time.Time, stopsAt time.Time) (int64, int64, bool) {
	splitDuration := int64(stopsAt.Sub(startsAt).Seconds())
	a, safe := mulInt64(int64(price), splitDuration)
	if !safe {
		return 0, 0, false
	}
	costWithoutFee, safe := mulInt64(a, int64(bw))
	if !safe {
		return 0, 0, false
	}
	fee := int64(float64(costWithoutFee)*float64(s.transactionFeeRelative)) + int64(s.transactionFeeAbsolute)
	return costWithoutFee, fee, true
}
func (s *MarketplaceStorage) IncrementASJWTVersion(ctx context.Context, ia addr.IA, current int64) (int64, error) {
	return s.db.IncrementASJWTVersion(ctx, ia, current)
}
func (s *MarketplaceStorage) IncrementUserJWTVersion(ctx context.Context, userid int64, current int64) (int64, error) {
	return s.db.IncrementUserJWTVersion(ctx, userid, current)
}

func gcd(a, b uint32) uint32 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func lcm(a, b uint32) uint32 {
	return a / gcd(a, b) * b
}

func (s *MarketplaceStorage) CombineAssets(ctx context.Context, user_id int64, assetId1 int64, assetId2 int64) (int64, error) {
	tx, err := s.db.BeginTransaction(ctx, &sql.TxOptions{})
	if err != nil {
		return 0, err
	}
	_, err = tx.UpdateMoney(ctx, user_id, -int64(s.splitCombineFeeAbsolute))
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	a1, err := tx.PrepareCombine(ctx, assetId1, user_id)
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	a2, err := tx.PrepareCombine(ctx, assetId2, user_id)
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	if a1.IA != a2.IA {
		return 0, serrors.Join(serrors.New("asset must have same IA"), tx.Rollback())
	}
	if a1.IfIdIngress.Valid && a1.IfIdIngress.Int32 != a2.IfIdIngress.Int32 {
		return 0, serrors.Join(serrors.New("asset must have same ingress"), tx.Rollback())
	}
	if a1.IfIdEgress.Valid && a1.IfIdEgress.Int32 != a2.IfIdEgress.Int32 {
		return 0, serrors.Join(serrors.New("asset must have same egress"), tx.Rollback())
	}
	var combinedAsset *marketplacedb.DBAsset
	if a1.StartAt.Equal(a2.StartAt) && a1.StopsAt.Equal(a2.StopsAt) {
		combinedAsset = &marketplacedb.DBAsset{
			OwnerId:         a1.OwnerId,
			IA:              a1.IA,
			Bandwidth:       a1.Bandwidth + a2.Bandwidth,
			BandwidthMin:    max(a1.BandwidthMin, a2.BandwidthMin),
			BandwidthMax:    min(a1.BandwidthMax, a2.BandwidthMax),
			StartAt:         a1.StartAt,
			StopsAt:         a1.StopsAt,
			Price:           0,
			TimeGranularity: lcm(a1.TimeGranularity, a2.TimeGranularity),
			TimeMinDuration: max(a1.TimeMinDuration, a2.TimeMinDuration),
			IfIdIngress:     a1.IfIdIngress,
			IfIdEgress:      a1.IfIdEgress,
		}
	} else if a1.Bandwidth == a2.Bandwidth {
		if a1.StartAt.Equal(a2.StopsAt) {
			combinedAsset = &marketplacedb.DBAsset{
				OwnerId:         a1.OwnerId,
				IA:              a1.IA,
				Bandwidth:       a1.Bandwidth,
				BandwidthMin:    max(a1.BandwidthMin, a2.BandwidthMin),
				BandwidthMax:    min(a1.BandwidthMax, a2.BandwidthMax),
				StartAt:         a2.StartAt,
				StopsAt:         a1.StopsAt,
				Price:           0,
				TimeGranularity: lcm(a1.TimeGranularity, a2.TimeGranularity),
				TimeMinDuration: max(a1.TimeMinDuration, a2.TimeMinDuration),
				IfIdIngress:     a1.IfIdIngress,
				IfIdEgress:      a1.IfIdEgress,
			}
		} else if a2.StartAt.Equal(a1.StopsAt) {
			combinedAsset = &marketplacedb.DBAsset{
				OwnerId:         a1.OwnerId,
				IA:              a1.IA,
				Bandwidth:       a1.Bandwidth,
				BandwidthMin:    max(a1.BandwidthMin, a2.BandwidthMin),
				BandwidthMax:    min(a1.BandwidthMax, a2.BandwidthMax),
				StartAt:         a1.StartAt,
				StopsAt:         a2.StopsAt,
				Price:           0,
				TimeGranularity: lcm(a1.TimeGranularity, a2.TimeGranularity),
				TimeMinDuration: max(a1.TimeMinDuration, a2.TimeMinDuration),
				IfIdIngress:     a1.IfIdIngress,
				IfIdEgress:      a1.IfIdEgress,
			}
		} else {
			return 0, serrors.Join(serrors.New("asset cannot be combined"), tx.Rollback())
		}
	} else {
		return 0, serrors.Join(serrors.New("asset cannot be combined"), tx.Rollback())
	}
	err = tx.RemoveAsset(ctx, assetId1)
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	err = tx.RemoveAsset(ctx, assetId2)
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	newId, err := tx.InsertAsset(ctx, combinedAsset)
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	err = tx.Commit()
	if err != nil {
		return 0, serrors.Join(err, tx.Rollback())
	}
	return newId, nil
}

func (s *MarketplaceStorage) SplitAsset(ctx context.Context, user_id int64, assetId int64, bwSplit *uint32, timeSplit *time.Time) (int64, int64, error) {
	if bwSplit == nil && timeSplit == nil {
		return 0, 0, serrors.New("invalid split request")
	}
	tx, err := s.db.BeginTransaction(ctx, &sql.TxOptions{})
	if err != nil {
		return 0, 0, err
	}
	_, err = tx.UpdateMoney(ctx, user_id, -int64(s.splitCombineFeeAbsolute))
	if err != nil {
		return 0, 0, serrors.Join(err, tx.Rollback())
	}
	dbAsset, err := tx.PrepareSplit(ctx, assetId, user_id)
	if err != nil {
		return 0, 0, serrors.Join(err, tx.Rollback())
	}
	var requestedSplit []RequestedSplit

	if bwSplit != nil {
		requestedSplit = []RequestedSplit{
			{
				ExactBandwidth: *bwSplit,
				ExactFrom:      dbAsset.StartAt,
				ExactTo:        dbAsset.StopsAt,
			},
			{
				ExactBandwidth: dbAsset.Bandwidth - *bwSplit,
				ExactFrom:      dbAsset.StartAt,
				ExactTo:        dbAsset.StopsAt,
			},
		}
	} else {
		requestedSplit = []RequestedSplit{
			{
				ExactBandwidth: dbAsset.Bandwidth,
				ExactFrom:      dbAsset.StartAt,
				ExactTo:        *timeSplit,
			},
			{
				ExactBandwidth: dbAsset.Bandwidth,
				ExactFrom:      *timeSplit,
				ExactTo:        dbAsset.StopsAt,
			},
		}
	}
	splitResult, err := SplitAsset(dbAsset, requestedSplit)
	if err != nil {
		return 0, 0, serrors.Join(err, tx.Rollback())
	}
	if !(len(splitResult.Bought) == 2 && len(splitResult.Unused) == 0) {
		return 0, 0, serrors.Join(serrors.New("invalid split result"), tx.Rollback())
	}
	asset1 := &marketplacedb.DBAsset{
		OwnerId:         dbAsset.OwnerId,
		IA:              dbAsset.IA,
		BandwidthMin:    dbAsset.BandwidthMin,
		BandwidthMax:    dbAsset.BandwidthMax,
		Price:           dbAsset.Price,
		TimeGranularity: dbAsset.TimeGranularity,
		TimeMinDuration: dbAsset.TimeMinDuration,
		IfIdIngress:     dbAsset.IfIdIngress,
		IfIdEgress:      dbAsset.IfIdEgress,
		Bandwidth:       splitResult.Bought[0].Bandwidth,
		StartAt:         splitResult.Bought[0].StartAt,
		StopsAt:         splitResult.Bought[0].StopAt,
	}
	asset2 := &marketplacedb.DBAsset{
		OwnerId:         dbAsset.OwnerId,
		IA:              dbAsset.IA,
		BandwidthMin:    dbAsset.BandwidthMin,
		BandwidthMax:    dbAsset.BandwidthMax,
		Price:           dbAsset.Price,
		TimeGranularity: dbAsset.TimeGranularity,
		TimeMinDuration: dbAsset.TimeMinDuration,
		IfIdIngress:     dbAsset.IfIdIngress,
		IfIdEgress:      dbAsset.IfIdEgress,
		Bandwidth:       splitResult.Bought[1].Bandwidth,
		StartAt:         splitResult.Bought[1].StartAt,
		StopsAt:         splitResult.Bought[1].StopAt,
	}
	err = tx.RemoveAsset(ctx, assetId)
	if err != nil {
		return 0, 0, serrors.Join(err, tx.Rollback())
	}
	assetId1, err := tx.InsertAsset(ctx, asset1)
	if err != nil {
		return 0, 0, serrors.Join(err, tx.Rollback())
	}
	assetId2, err := tx.InsertAsset(ctx, asset2)
	if err != nil {
		return 0, 0, serrors.Join(err, tx.Rollback())
	}
	err = tx.Commit()
	if err != nil {
		return 0, 0, serrors.Join(err, tx.Rollback())
	}
	return assetId1, assetId2, nil
}

func (s *MarketplaceStorage) Statistics(ctx context.Context, params *marketplacedb.StatisticsQuery) ([]*marketplacedb.DBStat, error) {
	return s.db.SearchAssetsForStatistics(ctx, params)
}

func (s *MarketplaceStorage) FindUsedReservations(ctx context.Context, params *marketplacedb.UsedReservationsQuery) ([]*marketplacedb.UsedReservation, error) {
	return s.db.FindUsedReservations(ctx, params)
}

func (s *MarketplaceStorage) BuyAssets(ctx context.Context, user_id int64, assets []*hummingbird.BuyAsset, maxPrice uint64) ([]int64, int64, error) {
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
		dbAsset, err := tx.CheckoutAsset(ctx, assetId)
		if err != nil {
			return nil, 0, serrors.Join(err, tx.Rollback())
		}
		split, err := SplitAsset(dbAsset, []RequestedSplit{
			{
				ExactFrom:      asset.StartsAtExactly.AsTime(),
				ExactTo:        asset.StopsAtExactly.AsTime(),
				ExactBandwidth: asset.BandwidthExact,
			},
		})
		if err != nil {
			return nil, 0, serrors.Join(err, tx.Rollback())
		}
		for _, segment := range split.Bought {
			newAsset := &marketplacedb.DBAsset{
				OwnerId: sql.NullInt64{
					Int64: user_id,
					Valid: true,
				},
				IA:              dbAsset.IA,
				BandwidthMin:    dbAsset.BandwidthMin,
				BandwidthMax:    dbAsset.BandwidthMax,
				TimeGranularity: dbAsset.TimeGranularity,
				TimeMinDuration: dbAsset.TimeMinDuration,
				IfIdIngress:     dbAsset.IfIdIngress,
				IfIdEgress:      dbAsset.IfIdEgress,
				Bandwidth:       segment.Bandwidth,
				StartAt:         segment.StartAt,
				StopsAt:         segment.StopAt,
				Price:           dbAsset.Price,
			}
			id, err := tx.InsertAsset(ctx, newAsset)
			if err != nil {
				return nil, 0, serrors.Join(err, tx.Rollback())
			}
			totalAssetPrice, fee, safe := s.totalPrice(dbAsset.Price, segment.Bandwidth, segment.StartAt, segment.StopAt)
			if !safe {
				return nil, 0, serrors.Join(serrors.New("total asset price would lead to integer overflow"), tx.Rollback())
			}
			pricePlusFee, safe := addInt64(totalAssetPrice, fee)
			if !safe {
				return nil, 0, serrors.Join(serrors.New("total asset price would lead to integer overflow"), tx.Rollback())
			}
			_, err = tx.UpdateASMoney(ctx, dbAsset.IA, totalAssetPrice)
			if err != nil {
				return nil, 0, serrors.Join(err, tx.Rollback())
			}
			costAcc, safe = addInt64(costAcc, pricePlusFee) // currently fee is deducted but the marketplace cannot really see their actual income
			if !safe {
				return nil, 0, serrors.Join(serrors.New("total asset price would lead to integer overflow"), tx.Rollback())
			}
			boughtAssets = append(boughtAssets, id)
		}
		for _, segment := range split.Unused {
			newAsset := &marketplacedb.DBAsset{
				IA:              dbAsset.IA,
				BandwidthMin:    dbAsset.BandwidthMin,
				BandwidthMax:    dbAsset.BandwidthMax,
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
	_, err = tx.UpdateMoney(ctx, user_id, -costAcc)
	if err != nil {
		return nil, 0, serrors.Join(err, tx.Rollback())
	}
	err = tx.Commit()
	if err != nil {
		return nil, 0, serrors.Join(err, tx.Rollback())
	}
	return boughtAssets, costAcc, nil
}

func (s *MarketplaceStorage) InsertReservation(ctx context.Context, r *marketplacedb.DBReservation) (int64, error) {
	return s.db.InsertReservation(ctx, r)
}

func (s *MarketplaceStorage) UndoRedemption(ctx context.Context, user_id int64, ingressIDString *string, egressIDString *string, pairIDString *string) error {
	tx, err := s.db.BeginTransaction(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	if ingressIDString != nil && egressIDString != nil {
		ingressID, err := strconv.ParseInt(*ingressIDString, 10, 64)
		if err != nil {
			return serrors.Join(err, tx.Rollback())
		}
		egressID, err := strconv.ParseInt(*egressIDString, 10, 64)
		if err != nil {
			return serrors.Join(err, tx.Rollback())
		}
		n, err := tx.UndoRedemption(ctx, user_id, ingressID)
		if err != nil {
			return serrors.Join(err, tx.Rollback())
		}
		if n != 1 {
			return serrors.Join(serrors.New("asset not found"), tx.Rollback())
		}
		n, err = tx.UndoRedemption(ctx, user_id, egressID)
		if err != nil {
			return serrors.Join(err, tx.Rollback())
		}
		if n != 1 {
			return serrors.Join(serrors.New("asset not found"), tx.Rollback())
		}
		return tx.Commit()
	} else if ingressIDString == nil && egressIDString == nil && pairIDString != nil {
		pairID, err := strconv.ParseInt(*pairIDString, 10, 64)
		if err != nil {
			return serrors.Join(err, tx.Rollback())
		}
		n, err := tx.UndoRedemption(ctx, user_id, pairID)
		if err != nil {
			return serrors.Join(err, tx.Rollback())
		}
		if n != 1 {
			return serrors.Join(serrors.New("asset not found"), tx.Rollback())
		}
		return tx.Commit()
	}
	return serrors.Join(serrors.New("invalid asset IDs"), tx.Rollback())
}
func validateAsset(a *marketplacedb.DBAsset) error {
	duration := a.StopsAt.Sub(a.StartAt)
	if a.Bandwidth == 0 {
		return serrors.New("bandwidth is 0")
	}
	if duration == 0 {
		return serrors.New("duration is 0")
	}
	if a.Bandwidth < a.BandwidthMin {
		return serrors.New("bandwidth < min_bandwidth")
	}
	if a.Bandwidth > a.BandwidthMax {
		return serrors.New("bandwith > max_bandiwdth")
	}
	if duration < time.Duration(a.TimeMinDuration)*time.Second {
		return serrors.New("duration < time_min_duration")
	}
	if duration%(time.Duration(a.TimeGranularity)*time.Second) != 0 {
		return serrors.New("duration not multiple of time granularity")
	}
	return nil
}
func (s *MarketplaceStorage) PrepareRedemption(ctx context.Context, user_id int64, ingressIDString *string, egressIDString *string, pairIDString *string) ([]*marketplacedb.DBAsset, error) {
	tx, err := s.db.BeginTransaction(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, err
	}
	if ingressIDString != nil && egressIDString != nil {
		ingressID, err := strconv.ParseInt(*ingressIDString, 10, 64)
		if err != nil {
			return nil, serrors.Join(err, tx.Rollback())
		}
		egressID, err := strconv.ParseInt(*egressIDString, 10, 64)
		if err != nil {
			return nil, serrors.Join(err, tx.Rollback())
		}
		ingressAsset, err := tx.PrepareRedemption(ctx, user_id, ingressID)
		if err != nil {
			return nil, serrors.Join(err, tx.Rollback())
		}
		if !ingressAsset.IfIdIngress.Valid || ingressAsset.IfIdEgress.Valid {
			return nil, serrors.Join(serrors.New("ingress asset is not an ingress asset"), tx.Rollback())
		}
		if err = validateAsset(ingressAsset); err != nil {
			return nil, serrors.Join(err, tx.Rollback())
		}
		egressAsset, err := tx.PrepareRedemption(ctx, user_id, egressID)
		if err != nil {
			return nil, serrors.Join(err, tx.Rollback())
		}
		if !egressAsset.IfIdEgress.Valid || egressAsset.IfIdIngress.Valid {
			return nil, serrors.Join(serrors.New("egress asset is not an egress asset"), tx.Rollback())
		}
		if err = validateAsset(egressAsset); err != nil {
			return nil, serrors.Join(err, tx.Rollback())
		}
		err = tx.Commit()
		if err != nil {
			return nil, serrors.Join(err, tx.Rollback())
		}
		return []*marketplacedb.DBAsset{ingressAsset, egressAsset}, nil
	} else if ingressIDString == nil && egressIDString == nil && pairIDString != nil {
		pairID, err := strconv.ParseInt(*pairIDString, 10, 64)
		if err != nil {
			return nil, serrors.Join(err, tx.Rollback())
		}
		pairAsset, err := tx.PrepareRedemption(ctx, user_id, pairID)
		if err != nil {
			return nil, serrors.Join(err, tx.Rollback())
		}
		if !pairAsset.IfIdIngress.Valid || !pairAsset.IfIdEgress.Valid {
			return nil, serrors.Join(serrors.New("pair asset is not a pair asset"), tx.Rollback())
		}
		if err = validateAsset(pairAsset); err != nil {
			return nil, serrors.Join(err, tx.Rollback())
		}
		err = tx.Commit()
		if err != nil {
			return nil, serrors.Join(err, tx.Rollback())
		}
		return []*marketplacedb.DBAsset{pairAsset}, nil
	}
	return nil, serrors.Join(serrors.New("invalid asset IDs"), tx.Rollback())

}

func (s *MarketplaceStorage) DepositMoneyAndGet(ctx context.Context, id int64, amount int64) (*marketplacedb.DBUser, error) {
	tx, err := s.db.BeginTransaction(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, err
	}
	_, err = tx.UpdateMoney(ctx, id, amount)
	if err != nil {
		return nil, serrors.Join(err, tx.Rollback())
	}
	user, err := tx.GetUser(ctx, id)
	if err != nil {
		return nil, serrors.Join(err, tx.Rollback())
	}
	err = tx.Commit()
	if err != nil {
		return nil, serrors.Join(err, tx.Rollback())
	}
	return user, nil
}

func (s *MarketplaceStorage) DepositMoneyAndGetAS(ctx context.Context, ia addr.IA, amount int64) (*marketplacedb.DBASUser, error) {
	tx, err := s.db.BeginTransaction(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, err
	}
	_, err = tx.UpdateASMoney(ctx, ia, amount)
	if err != nil {
		return nil, serrors.Join(err, tx.Rollback())
	}
	user, err := tx.GetASUser(ctx, ia)
	if err != nil {
		return nil, serrors.Join(err, tx.Rollback())
	}
	err = tx.Commit()
	if err != nil {
		return nil, serrors.Join(err, tx.Rollback())
	}
	return user, nil
}
