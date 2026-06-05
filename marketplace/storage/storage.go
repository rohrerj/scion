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

	marketplacedb "github.com/scionproto/scion/marketplace/db"
	"github.com/scionproto/scion/pkg/private/serrors"
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
	return s.db.PublishAsset(ctx, a)
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

func (s *MarketplaceStorage) DepositMoneyAndGet(ctx context.Context, name string, amount int64) (*marketplacedb.DBUser, error) {
	tx, err := s.db.BeginTransaction(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, err
	}
	_, err = tx.DepositMoney(ctx, name, amount)
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
