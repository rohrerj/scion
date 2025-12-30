// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/scionproto/scion/pkg/log"
)

type DataQuerier struct {
	pool *pgxpool.Pool
}

type Row struct {
	Data              [32]byte
	Ingress           int16
	Egress            int16
	Counter           uint32
	IsIngress         bool
	SourceIAAggregate string
}

func SetupDataQuerier(ctx context.Context, connStr string) (*DataQuerier, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, err
	}
	d := &DataQuerier{
		pool: pool,
	}
	return d, nil
}

func (d *DataQuerier) Query(ctx context.Context, start time.Time, end time.Time, index int) ([]Row, error) {
	rows, err := d.pool.Query(
		ctx,
		`SELECT data, ingress, egress, counter, is_ingress, source_ia_aggregate
     FROM buckets
     WHERE time_window = $1 and time >= $2 and time < $3`,
		index,
		start,
		end,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Row, 0)
	c := 0
	for rows.Next() {
		c++
		var r Row
		var data []byte
		err = rows.Scan(
			&data,
			&r.Ingress,
			&r.Egress,
			&r.Counter,
			&r.IsIngress,
			&r.SourceIAAggregate,
		)
		if err != nil {
			return nil, err
		}

		if len(data) != 32 {
			return nil, fmt.Errorf("invalid data length: %d", len(data))
		}
		copy(r.Data[:], data)
		result = append(result, r)
	}
	log.Debug("returned row count", "count", c)
	return result, rows.Err()
}
