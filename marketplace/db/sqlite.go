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

package db

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/storage/db"
)

type MarketplaceDB interface {
	io.Closer
	InsertAsset(ctx context.Context, a *DBAsset) (int64, error)
	InsertReservation(ctx context.Context, r *DBReservation) (int64, error)
	Search(ctx context.Context, params *AssetQuery) ([]*DBAsset, error)
	FetchReservations(ctx context.Context, params *ReservationQuery) ([]*DBReservation, error)
	GetUser(ctx context.Context, id int64) (*DBUser, error)
	GetUserByName(ctx context.Context, name string) (*DBUser, error)
	CreateUser(ctx context.Context, user *DBUser) (int64, error)
	CreateASUser(ctx context.Context, user *DBASUser) (int64, error)
	UpdateMoney(ctx context.Context, id int64, amount int64) (int64, error)
	UpdateASMoney(ctx context.Context, ia addr.IA, amount int64) (int64, error)
	SearchAssetsForStatistics(ctx context.Context, params *StatisticsQuery) ([]*DBStat, error)
	FindUsedReservations(ctx context.Context, params *UsedReservationsQuery) ([]*UsedReservation, error)
	CreateOrUpdateRedemptionDelegations(ctx context.Context, r *RedemptionDelegation) (int64, error)
	FindRedemptionDelegations(ctx context.Context) ([]*RedemptionDelegation, error)
	IncrementASJWTVersion(ctx context.Context, ia addr.IA, current int64) (int64, error)
	IncrementUserJWTVersion(ctx context.Context, userid int64, current int64) (int64, error)
	GetASUser(ctx context.Context, ia addr.IA) (*DBASUser, error)
	DeleteListedAsset(ctx context.Context, ia addr.IA, assetID int64) (int64, error)
	SetASAuthenticationToken(ctx context.Context, ia addr.IA, auth string) (int64, error)
	BeginTransaction(ctx context.Context, opts *sql.TxOptions) (*transaction, error)
}

type Backend struct {
	db *db.Sqlite
	*executor
}

type executor struct {
	write db.Sqler
	read  interface {
		QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
		QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	}
}

func New(path string, cfg *db.SqliteConfig) (*Backend, error) {
	db, err := db.NewSqlite(path, cfg)
	if err != nil {
		return nil, err
	}
	if err := db.Setup(Schema, SchemaVersion); err != nil {
		return nil, err
	}
	return &Backend{
		executor: &executor{
			write: db.Full,
			read:  db.ReadOnly,
		},
		db: db,
	}, nil
}

func (b *Backend) Close() error {
	return b.db.Close()
}

func (b *Backend) BeginTransaction(ctx context.Context, opts *sql.TxOptions) (*transaction, error) {
	tx, err := b.db.Full.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &transaction{
		executor: &executor{
			write: tx,
			read:  tx,
		},
		tx: tx,
	}, nil
}

type transaction struct {
	*executor
	tx *sql.Tx
}

func (tx *transaction) Commit() error {
	return tx.tx.Commit()
}

func (tx *transaction) Rollback() error {
	return tx.tx.Rollback()
}

func (e *executor) FetchReservations(ctx context.Context, params *ReservationQuery) ([]*DBReservation, error) {
	if e.read == nil {
		return nil, serrors.New("No database open")
	}
	stmt, args := e.buildReservationQuery(params)
	rows, err := e.read.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, serrors.New("Error looking up assets", "err", err, "q", stmt)
	}
	defer rows.Close()
	var res []*DBReservation
	for rows.Next() {
		a := &DBReservation{}
		var startsAtString string
		var stopsAtString string
		var isd uint16
		var as uint64
		err = rows.Scan(&a.ID, &isd, &as, &a.Ingress, &a.Egress, &a.Bandwidth, &a.EncodedBandwidth, &startsAtString, &stopsAtString, &a.Key)
		if err != nil {
			return nil, serrors.Wrap("Error reading DB response", err)
		}
		a.IA, err = addr.IAFrom(addr.ISD(isd), addr.AS(as))
		a.StartsAt, err = time.Parse(time.RFC3339, startsAtString)
		if err != nil {
			return nil, err
		}
		a.StopsAt, err = time.Parse(time.RFC3339, stopsAtString)
		if err != nil {
			return nil, err
		}
		res = append(res, a)
	}
	return res, nil
}

func (e *executor) buildReservationQuery(params *ReservationQuery) (string, []any) {
	var args []any
	where := []string{}
	query := []string{
		"SELECT id, isd_id, as_id, ingress, egress, bandwidth, bw_encoded, starts_at, stops_at, key FROM Reservations",
	}
	where = append(where, "(owner_id = ?)")
	args = append(args, params.OwnerId)
	if params.IA != nil {
		where = append(where, "(isd_id=?) AND (as_id=?)")
		args = append(args, int64(params.IA.ISD()), int64(params.IA.AS()))
	}
	if params.StartsAt != nil {
		where = append(where, "(starts_at<=?)")
		args = append(args, *params.StartsAt)
	}
	if params.StopsAt != nil {
		where = append(where, "(stops_at>=?)")
		args = append(args, *params.StopsAt)
	}
	if params.Ingress != nil {
		where = append(where, "(ingress=?)")
		args = append(args, *params.Ingress)
	}
	if params.Egress != nil {
		where = append(where, "(egress=?)")
		args = append(args, *params.Egress)
	}
	if params.Bandwidth != nil {
		where = append(where, "(bandwidth>=?)")
		args = append(args, *params.Bandwidth)
	}
	query = append(query, fmt.Sprintf("WHERE %s", strings.Join(where, "AND\n")))
	return strings.Join(query, "\n"), args
}

func (e *executor) FindRedemptionDelegations(ctx context.Context) ([]*RedemptionDelegation, error) {
	if e.read == nil {
		return nil, serrors.New("No database open")
	}
	stmt := `SELECT isd_id, as_id, res_id_limit, expiration, paid_until, key, encodings FROM Redemption_Delegations WHERE expiration >= ?`
	args := []any{time.Now().Format(time.RFC3339)}
	rows, err := e.read.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, serrors.New("Error looking up assets", "err", err, "q", stmt)
	}
	defer rows.Close()
	var res []*RedemptionDelegation
	for rows.Next() {
		a := &RedemptionDelegation{}
		var expirationString string
		var paidUntilString string
		var isd uint16
		var as uint64
		err = rows.Scan(&isd, &as, &a.ReservationIdLimit, &expirationString, &paidUntilString, &a.Key, &a.Encodings)
		if err != nil {
			return nil, serrors.Wrap("Error reading DB response", err)
		}
		a.Expiration, err = time.Parse(time.RFC3339, expirationString)
		if err != nil {
			return nil, err
		}
		a.PaidUntil, err = time.Parse(time.RFC3339, paidUntilString)
		if err != nil {
			return nil, err
		}
		a.IA, err = addr.IAFrom(addr.ISD(isd), addr.AS(as))
		res = append(res, a)
	}
	return res, nil
}

func (e *executor) FindRedemptionDelegation(ctx context.Context, ia addr.IA) (*RedemptionDelegation, error) {
	if e.read == nil {
		return nil, serrors.New("No database open")
	}
	stmt := `SELECT isd_id, as_id, res_id_limit, expiration, paid_until, key, encodings FROM Redemption_Delegations WHERE expiration >= ? AND isd_id = ? AND as_id = ?`
	rows, err := e.read.QueryContext(ctx, stmt, time.Now().Format(time.RFC3339), ia.ISD(), ia.AS())
	if err != nil {
		return nil, serrors.New("Error looking up assets", "err", err, "q", stmt)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	a := &RedemptionDelegation{}
	var expirationString string
	var paidUntilString string
	var isd uint16
	var as uint64
	err = rows.Scan(&isd, &as, &a.ReservationIdLimit, &expirationString, &paidUntilString, &a.Key, &a.Encodings)
	if err != nil {
		return nil, serrors.Wrap("Error reading DB response", err)
	}
	a.Expiration, err = time.Parse(time.RFC3339, expirationString)
	if err != nil {
		return nil, err
	}
	a.PaidUntil, err = time.Parse(time.RFC3339, paidUntilString)
	if err != nil {
		return nil, err
	}
	a.IA, err = addr.IAFrom(addr.ISD(isd), addr.AS(as))
	return a, nil
}

func (e *executor) IncrementASJWTVersion(ctx context.Context, ia addr.IA, current int64) (int64, error) {
	if e.write == nil {
		return 0, serrors.New("No database open")
	}
	q := `UPDATE Ases SET jwt_version = jwt_version + 1 WHERE isd_id = ? AND as_id = ? AND jwt_version = ? RETURNING jwt_version`
	rows, err := e.write.QueryContext(ctx, q, ia.ISD(), ia.AS(), current)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, serrors.New("AS not found", "ia", ia)
	}
	var newVersion int64
	err = rows.Scan(&newVersion)
	if err != nil {
		return 0, serrors.Wrap("Error reading DB response", err)
	}
	return newVersion, nil
}

func (e *executor) IncrementUserJWTVersion(ctx context.Context, userid int64, current int64) (int64, error) {
	if e.write == nil {
		return 0, serrors.New("No database open")
	}
	q := `UPDATE Users SET jwt_version = jwt_version + 1 WHERE id = ? AND jwt_version = ? RETURNING jwt_version`
	rows, err := e.write.QueryContext(ctx, q, userid, current)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, serrors.New("User not found", "userid", userid)
	}
	var newVersion int64
	err = rows.Scan(&newVersion)
	if err != nil {
		return 0, serrors.Wrap("Error reading DB response", err)
	}
	return newVersion, nil
}

func (e *executor) CreateOrUpdateRedemptionDelegations(ctx context.Context, r *RedemptionDelegation) (int64, error) {
	if e.write == nil {
		return 0, serrors.New("No database open")
	}
	q := `
	INSERT INTO Redemption_Delegations (isd_id, as_id, res_id_limit, expiration, paid_until, key, encodings)
	VALUES (?,?,?,?,?,?,?)
	ON CONFLICT(isd_id, as_id)
	DO UPDATE SET
		expiration = excluded.expiration,
		paid_until = excluded.paid_until,
		key = excluded.key,
		encodings = excluded.encodings,
		res_id_limit = excluded.res_id_limit;`
	res, err := e.write.ExecContext(ctx, q, r.IA.ISD(), r.IA.AS(), r.ReservationIdLimit, r.Expiration.Format(time.RFC3339),
		r.PaidUntil.Format(time.RFC3339), r.Key, r.Encodings)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (e *executor) FindUsedReservations(ctx context.Context, params *UsedReservationsQuery) ([]*UsedReservation, error) {
	if e.read == nil {
		return nil, serrors.New("No database open")
	}
	stmt, args := e.buildUsedReservationsQuery(params)
	rows, err := e.read.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, serrors.New("Error looking up assets", "err", err, "q", stmt)
	}
	defer rows.Close()
	var res []*UsedReservation
	for rows.Next() {
		a := &UsedReservation{}
		var startsAtString string
		var stopsAtString string
		err = rows.Scan(&a.Id, &startsAtString, &stopsAtString)
		if err != nil {
			return nil, serrors.Wrap("Error reading DB response", err)
		}
		a.StartsAt, err = time.Parse(time.RFC3339, startsAtString)
		if err != nil {
			return nil, err
		}
		a.StopsAt, err = time.Parse(time.RFC3339, stopsAtString)
		if err != nil {
			return nil, err
		}
		res = append(res, a)
	}
	return res, nil
}

func (e *executor) buildUsedReservationsQuery(params *UsedReservationsQuery) (string, []any) {
	var args []any
	query := []string{
		"SELECT id, starts_at, stops_at FROM Reservations",
		"WHERE (isd_id = ?) AND (as_id = ?) AND (starts_at >= ?) AND (stops_at < ?)",
	}
	// we want to find all reservations of the IA, that are at least partially valid withing our interval,
	// i.e. end of reservation must come after interval start and start of reservation must come before end of interval
	args = append(args, params.IA.ISD(), params.IA.AS(), params.StopsAt, params.StartsAt)
	return strings.Join(query, "\n"), args
}

func (e *executor) SearchAssetsForStatistics(ctx context.Context, params *StatisticsQuery) ([]*DBStat, error) {
	if e.read == nil {
		return nil, serrors.New("No database open")
	}
	stmt, args := e.buildStatisticsQuery(params)
	rows, err := e.read.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, serrors.New("Error looking up assets", "err", err, "q", stmt)
	}
	defer rows.Close()
	var res []*DBStat
	for rows.Next() {
		a := &DBStat{}
		var startsAtString string
		var stopsAtString string
		err = rows.Scan(&a.OwnerId, &a.Bandwidth, &a.Price, &startsAtString, &stopsAtString)
		if err != nil {
			return nil, serrors.Wrap("Error reading DB response", err)
		}
		a.StartsAt, err = time.Parse(time.RFC3339, startsAtString)
		if err != nil {
			return nil, err
		}
		a.StopsAt, err = time.Parse(time.RFC3339, stopsAtString)
		if err != nil {
			return nil, err
		}
		res = append(res, a)
	}
	return res, nil
}

func (e *executor) buildStatisticsQuery(params *StatisticsQuery) (string, []any) {
	var args []any
	where := []string{}
	query := []string{
		"SELECT owner_id, bandwidth, price, starts_at, stops_at FROM Assets",
	}
	where = append(where, "(isd_id=?) AND (as_id=?) AND (stops_at > ?) AND (starts_at <= ?)")
	args = append(args, int64(params.IA.ISD()), int64(params.IA.AS()), params.WindowStart, params.WindowEnd)
	if params.Ingress != nil {
		where = append(where, "(ingress=?)")
		args = append(args, *params.Ingress)
	}
	if params.Egress != nil {
		where = append(where, "(egress=?)")
		args = append(args, *params.Egress)
	}
	query = append(query, fmt.Sprintf("WHERE %s", strings.Join(where, "AND\n")))
	return strings.Join(query, "\n"), args
}

func (e *executor) Search(ctx context.Context, params *AssetQuery) ([]*DBAsset, error) {
	if e.read == nil {
		return nil, serrors.New("No database open")
	}
	stmt, args := e.buildSearchQuery(params)
	rows, err := e.read.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, serrors.New("Error looking up assets", "err", err, "q", stmt)
	}
	defer rows.Close()
	var res []*DBAsset
	for rows.Next() {
		a := &DBAsset{}
		var startsAtString string
		var stopsAtString string
		var isd uint16
		var as uint64
		err = rows.Scan(&a.ID, &a.OwnerId, &isd, &as, &a.Bandwidth, &a.BandwidthMin, &a.BandwidthMax, &a.Price, &a.TimeGranularity, &a.TimeMinDuration, &startsAtString, &stopsAtString, &a.IfIdIngress, &a.IfIdEgress)
		if err != nil {
			return nil, serrors.Wrap("Error reading DB response", err)
		}
		a.IA, err = addr.IAFrom(addr.ISD(isd), addr.AS(as))
		a.StartAt, err = time.Parse(time.RFC3339, startsAtString)
		if err != nil {
			return nil, err
		}
		a.StopsAt, err = time.Parse(time.RFC3339, stopsAtString)
		if err != nil {
			return nil, err
		}
		res = append(res, a)
	}
	return res, nil
}

func (e *executor) buildSearchQuery(params *AssetQuery) (string, []any) {
	var args []any
	where := []string{}
	query := []string{
		"SELECT id, owner_id, isd_id, as_id, bandwidth, bandwidth_min, bandwidth_max, price, time_granularity, time_min_duration, starts_at, stops_at, ingress, egress FROM Assets",
	}
	where = append(where, "(state = 0)")
	if params.OwnerId == nil {
		where = append(where, "(owner_id IS NULL)")
	} else {
		where = append(where, "(owner_id=?)")
		args = append(args, *params.OwnerId)
	}
	if params.IA != nil {
		where = append(where, "(isd_id=?) AND (as_id=?)")
		args = append(args, int64(params.IA.ISD()), int64(params.IA.AS()))
	}
	if params.StartsAt != nil {
		where = append(where, "(starts_at<=?)")
		args = append(args, *params.StartsAt)
	}
	if params.StopsAt != nil {
		where = append(where, "(stops_at>=?)")
		args = append(args, *params.StopsAt)
	}
	if params.Price != nil {
		where = append(where, "(price<=?)")
		args = append(args, *params.Price)
	}
	if params.MinRequiredBandwidth != nil {
		where = append(where, "(bandwidth>=?)")
		args = append(args, *params.MinRequiredBandwidth)
	}
	if params.Ingress != nil {
		where = append(where, "(ingress=?)")
		args = append(args, *params.Ingress)
	}
	if params.Egress != nil {
		where = append(where, "(egress=?)")
		args = append(args, *params.Egress)
	}
	query = append(query, fmt.Sprintf("WHERE %s", strings.Join(where, "AND\n")))
	query = append(query, "ORDER BY LENGTH(id) ASC, id ASC")
	return strings.Join(query, "\n"), args
}

func (e *executor) PrepareCombine(ctx context.Context, id int64, userId int64) (*DBAsset, error) {
	if e.write == nil {
		return nil, serrors.New("No database open")
	}
	q := `
	UPDATE assets
	SET state = 4
	WHERE id = ?
	AND state = 0
	AND owner_id = ?
	RETURNING
		id,
		owner_id,
		isd_id,
		as_id,
		bandwidth,
		bandwidth_min,
		bandwidth_max,
		price,
		time_granularity,
		time_min_duration,
		starts_at,
		stops_at,
		ingress,
		egress;`
	rows, err := e.write.QueryContext(ctx, q, id, userId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, serrors.New("asset not found", "id", id)
	}
	a := &DBAsset{}
	var startsAtString string
	var stopsAtString string
	var isd uint16
	var as uint64
	err = rows.Scan(&a.ID, &a.OwnerId, &isd, &as, &a.Bandwidth, &a.BandwidthMin, &a.BandwidthMax, &a.Price, &a.TimeGranularity, &a.TimeMinDuration, &startsAtString, &stopsAtString, &a.IfIdIngress, &a.IfIdEgress)
	if err != nil {
		return nil, serrors.Wrap("Error reading DB response", err)
	}
	a.IA, err = addr.IAFrom(addr.ISD(isd), addr.AS(as))
	a.StartAt, err = time.Parse(time.RFC3339, startsAtString)
	if err != nil {
		return nil, err
	}
	a.StopsAt, err = time.Parse(time.RFC3339, stopsAtString)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (e *executor) PrepareSplit(ctx context.Context, id int64, userId int64) (*DBAsset, error) {
	if e.write == nil {
		return nil, serrors.New("No database open")
	}
	q := `
	UPDATE assets
	SET state = 3
	WHERE id = ?
	AND state = 0
	AND owner_id = ?
	RETURNING
		id,
		owner_id,
		isd_id,
		as_id,
		bandwidth,
		bandwidth_min,
		bandwidth_max,
		price,
		time_granularity,
		time_min_duration,
		starts_at,
		stops_at,
		ingress,
		egress;`
	rows, err := e.write.QueryContext(ctx, q, id, userId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, serrors.New("asset not found", "id", id)
	}
	a := &DBAsset{}
	var startsAtString string
	var stopsAtString string
	var isd uint16
	var as uint64
	err = rows.Scan(&a.ID, &a.OwnerId, &isd, &as, &a.Bandwidth, &a.BandwidthMin, &a.BandwidthMax, &a.Price, &a.TimeGranularity, &a.TimeMinDuration, &startsAtString, &stopsAtString, &a.IfIdIngress, &a.IfIdEgress)
	if err != nil {
		return nil, serrors.Wrap("Error reading DB response", err)
	}
	a.IA, err = addr.IAFrom(addr.ISD(isd), addr.AS(as))
	a.StartAt, err = time.Parse(time.RFC3339, startsAtString)
	if err != nil {
		return nil, err
	}
	a.StopsAt, err = time.Parse(time.RFC3339, stopsAtString)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (e *executor) CheckoutAsset(ctx context.Context, id int64) (*DBAsset, error) {
	if e.write == nil {
		return nil, serrors.New("No database open")
	}
	q := `
	UPDATE assets
	SET state = 1
	WHERE id = ?
	AND state = 0
	AND owner_id IS NULL
	RETURNING
		id,
		isd_id,
		as_id,
		bandwidth,
		bandwidth_min,
		bandwidth_max,
		price,
		time_granularity,
		time_min_duration,
		starts_at,
		stops_at,
		ingress,
		egress;`
	rows, err := e.write.QueryContext(ctx, q, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, serrors.New("asset not found", "id", id)
	}
	a := &DBAsset{}
	var startsAtString string
	var stopsAtString string
	var isd uint16
	var as uint64
	err = rows.Scan(&a.ID, &isd, &as, &a.Bandwidth, &a.BandwidthMin, &a.BandwidthMax, &a.Price, &a.TimeGranularity, &a.TimeMinDuration, &startsAtString, &stopsAtString, &a.IfIdIngress, &a.IfIdEgress)
	if err != nil {
		return nil, serrors.Wrap("Error reading DB response", err)
	}
	a.IA, err = addr.IAFrom(addr.ISD(isd), addr.AS(as))
	a.StartAt, err = time.Parse(time.RFC3339, startsAtString)
	if err != nil {
		return nil, err
	}
	a.StopsAt, err = time.Parse(time.RFC3339, stopsAtString)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (e *executor) UndoRedemption(ctx context.Context, user_id int64, id int64) (int64, error) {
	if e.write == nil {
		return 0, serrors.New("No database open")
	}
	q := `
	UPDATE Assets
	SET state = 0
	WHERE id = ?
	AND owner_id = ?
	AND state = 2`

	res, err := e.write.ExecContext(ctx, q, id, user_id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (e *executor) PrepareRedemption(ctx context.Context, user_id int64, id int64) (*DBAsset, error) {
	if e.write == nil {
		return nil, serrors.New("No database open")
	}
	q := `
	UPDATE assets
	SET state = 2
	WHERE id = ?
	AND state = 0
	AND owner_id = ?
	RETURNING
		id,
		isd_id,
		as_id,
		bandwidth,
		bandwidth_min,
		bandwidth_max,
		price,
		time_granularity,
		time_min_duration,
		starts_at,
		stops_at,
		ingress,
		egress;`
	rows, err := e.write.QueryContext(ctx, q, id, user_id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, serrors.New("asset not found", "id", id)
	}
	a := &DBAsset{}
	var startsAtString string
	var stopsAtString string
	var isd uint16
	var as uint64
	err = rows.Scan(&a.ID, &isd, &as, &a.Bandwidth, &a.BandwidthMin, &a.BandwidthMax, &a.Price, &a.TimeGranularity, &a.TimeMinDuration, &startsAtString, &stopsAtString, &a.IfIdIngress, &a.IfIdEgress)
	if err != nil {
		return nil, serrors.Wrap("Error reading DB response", err)
	}
	a.IA, err = addr.IAFrom(addr.ISD(isd), addr.AS(as))
	a.StartAt, err = time.Parse(time.RFC3339, startsAtString)
	if err != nil {
		return nil, err
	}
	a.StopsAt, err = time.Parse(time.RFC3339, stopsAtString)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (e *executor) InsertReservation(ctx context.Context, r *DBReservation) (int64, error) {
	if e.write == nil {
		return 0, serrors.New("No database open")
	}
	q := `INSERT INTO Reservations (id, isd_id, as_id, ingress, egress, bandwidth, bw_encoded, starts_at, stops_at, key, owner_id)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`
	res, err := e.write.ExecContext(ctx, q, r.ID, r.IA.ISD(), r.IA.AS(), r.Ingress, r.Egress, r.Bandwidth, r.EncodedBandwidth,
		r.StartsAt.UTC().Format(time.RFC3339), r.StopsAt.UTC().Format(time.RFC3339),
		r.Key, r.OwnerId)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (e *executor) InsertAsset(ctx context.Context, a *DBAsset) (int64, error) {
	if e.write == nil {
		return 0, serrors.New("No database open")
	}
	var res sql.Result
	var err error
	if a.OwnerId.Valid {
		inst := `INSERT INTO Assets (isd_id, as_id, bandwidth, bandwidth_min, bandwidth_max, price, time_granularity,
	time_min_duration, starts_at, stops_at, ingress, egress, owner_id)
	VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`
		res, err = e.write.ExecContext(ctx, inst, a.IA.ISD(), a.IA.AS(), a.Bandwidth, a.BandwidthMin, a.BandwidthMax, a.Price, a.TimeGranularity,
			a.TimeMinDuration, a.StartAt.UTC().Format(time.RFC3339), a.StopsAt.UTC().Format(time.RFC3339), a.IfIdIngress, a.IfIdEgress, a.OwnerId.Int64)
	} else {
		inst := `INSERT INTO Assets (isd_id, as_id, bandwidth, bandwidth_min, bandwidth_max, price, time_granularity,
	time_min_duration, starts_at, stops_at, ingress, egress)
	VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`
		res, err = e.write.ExecContext(ctx, inst, a.IA.ISD(), a.IA.AS(), a.Bandwidth, a.BandwidthMin, a.BandwidthMax, a.Price, a.TimeGranularity,
			a.TimeMinDuration, a.StartAt.UTC().Format(time.RFC3339), a.StopsAt.UTC().Format(time.RFC3339), a.IfIdIngress, a.IfIdEgress)
	}
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (e *executor) DeleteListedAsset(ctx context.Context, ia addr.IA, assetID int64) (int64, error) {
	if e.write == nil {
		return 0, serrors.New("No database open")
	}
	inst := `DELETE FROM Assets WHERE id = ? AND isd_id = ? AND as_id = ? AND owner_id IS NULL AND state = 0`
	res, err := e.write.ExecContext(ctx, inst, assetID, ia.ISD(), ia.AS())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (e *executor) RemoveAsset(ctx context.Context, assetID int64) error {
	if e.write == nil {
		return serrors.New("No database open")
	}
	inst := `DELETE FROM Assets WHERE id = ?`
	_, err := e.write.ExecContext(ctx, inst, assetID)
	return err
}

func (e *executor) GetUser(ctx context.Context, id int64) (*DBUser, error) {
	if e.read == nil {
		return nil, serrors.New("No database open")
	}
	q := `SELECT id, name, pw_hash, jwt_version, balance FROM Users WHERE id=?`
	rows, err := e.read.QueryContext(ctx, q, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	user := &DBUser{}
	err = rows.Scan(&user.ID, &user.Name, &user.PasswordHash, &user.TokenVersion, &user.Balance)
	if err != nil {
		return nil, serrors.Wrap("Error reading DB response", err)
	}
	return user, nil
}
func (e *executor) GetUserByName(ctx context.Context, name string) (*DBUser, error) {
	if e.read == nil {
		return nil, serrors.New("No database open")
	}
	q := `SELECT id, name, pw_hash, balance FROM Users WHERE name=?`
	rows, err := e.read.QueryContext(ctx, q, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	user := &DBUser{}
	err = rows.Scan(&user.ID, &user.Name, &user.PasswordHash, &user.Balance)
	if err != nil {
		return nil, serrors.Wrap("Error reading DB response", err)
	}
	return user, nil
}

func (e *executor) CreateUser(ctx context.Context, user *DBUser) (int64, error) {
	if e.write == nil {
		return 0, serrors.New("No database open")
	}
	inst := `INSERT INTO Users (name, pw_hash, balance)
	VALUES(?,?,?) ON CONFLICT(name) DO NOTHING`
	res, err := e.write.ExecContext(ctx, inst, user.Name, user.PasswordHash, user.Balance)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (e *executor) CreateASUser(ctx context.Context, user *DBASUser) (int64, error) {
	if e.write == nil {
		return 0, serrors.New("No database open")
	}
	inst := `INSERT INTO Ases (isd_id, as_id) VALUES(?,?) ON CONFLICT DO NOTHING`
	res, err := e.write.ExecContext(ctx, inst, user.IA.ISD(), user.IA.AS())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (e *executor) GetASUser(ctx context.Context, ia addr.IA) (*DBASUser, error) {
	if e.read == nil {
		return nil, serrors.New("No database open")
	}
	q := `SELECT isd_id, as_id, pw_hash, jwt_version, balance FROM Ases WHERE isd_id=? AND as_id=?`
	rows, err := e.read.QueryContext(ctx, q, ia.ISD(), ia.AS())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	user := &DBASUser{}
	var isd uint16
	var as uint64
	err = rows.Scan(&isd, &as, &user.PasswordHash, &user.TokenVersion, &user.Balance)
	if err != nil {
		return nil, serrors.Wrap("Error reading DB response", err)
	}
	user.IA, err = addr.IAFrom(ia.ISD(), addr.AS(as))
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (e *executor) UpdateMoney(ctx context.Context, id int64, amount int64) (int64, error) {
	if e.write == nil {
		return 0, serrors.New("No database open")
	}
	inst := `UPDATE users SET balance = balance + ? WHERE id = ?`
	res, err := e.write.ExecContext(ctx, inst, amount, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (e *executor) UpdateASMoney(ctx context.Context, ia addr.IA, amount int64) (int64, error) {
	if e.write == nil {
		return 0, serrors.New("No database open")
	}
	inst := `UPDATE Ases SET balance = balance + ? WHERE isd_id = ? AND as_id = ?`
	res, err := e.write.ExecContext(ctx, inst, amount, ia.ISD(), ia.AS())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
func (e *executor) SetASAuthenticationToken(ctx context.Context, ia addr.IA, auth string) (int64, error) {
	if e.write == nil {
		return 0, serrors.New("No database open")
	}
	inst := `UPDATE Ases SET pw_hash = ? WHERE isd_id = ? AND as_id = ?`
	res, err := e.write.ExecContext(ctx, inst, auth, ia.ISD(), ia.AS())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
