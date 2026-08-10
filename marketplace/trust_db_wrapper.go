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
	"crypto/x509"
	"net"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/storage"
	storageTrust "github.com/scionproto/scion/private/storage/trust"
	"github.com/scionproto/scion/private/trust"
)

type DB_Wrapper struct {
	db      storage.TrustDB
	fetcher trust.Fetcher
	server  net.Addr
}

func FromTrustDB(db storage.TrustDB, fetcher trust.Fetcher, server net.Addr) *DB_Wrapper {
	return &DB_Wrapper{
		db:      db,
		fetcher: fetcher,
		server:  server,
	}
}

func (d *DB_Wrapper) Chain(ctx context.Context, b []byte) ([]*x509.Certificate, error) {
	return d.db.Chain(ctx, b)
}

func (d *DB_Wrapper) Chains(ctx context.Context, q trust.ChainQuery) ([][]*x509.Certificate, error) {
	return d.db.Chains(ctx, q)
}

func (d *DB_Wrapper) Close() error {
	return d.db.Close()
}

func (d *DB_Wrapper) InsertChain(ctx context.Context, c []*x509.Certificate) (bool, error) {
	return d.db.InsertChain(ctx, c)
}

func (d *DB_Wrapper) InsertTRC(ctx context.Context, trc cppki.SignedTRC) (bool, error) {
	return d.db.InsertTRC(ctx, trc)
}

func (d *DB_Wrapper) SignedTRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	trc, err := d.db.SignedTRC(ctx, id)
	if err == nil && !trc.IsZero() {
		return trc, nil
	}
	log.FromCtx(ctx).Debug("fetch trc from server")
	trc, err = d.fetcher.TRC(ctx, id, d.server)
	if err != nil {
		return trc, serrors.WrapNoStack("parsing TRC", err)
	}
	_, err = d.InsertTRC(ctx, trc)
	if err != nil {
		return trc, serrors.WrapNoStack("inserting TRC", err)
	}
	return trc, nil
}

func (d *DB_Wrapper) SignedTRCs(ctx context.Context, query storageTrust.TRCsQuery) (cppki.SignedTRCs, error) {
	return d.db.SignedTRCs(ctx, query)
}
