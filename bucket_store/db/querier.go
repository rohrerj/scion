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
)

type DataQuerier struct {
	pool *pgxpool.Pool
}

type Row struct {
	Data      [32]byte
	Ingress   int16
	Egress    *int16
	Counter   uint32
	IsIngress bool
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
		`SELECT data, ingress, egress, counter, is_ingress
     FROM buckets
     WHERE time BETWEEN $1 AND $2 AND time_window = $3`,
		start,
		end,
		index,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]Row, 0)

	for rows.Next() {
		var r Row
		var data []byte
		err = rows.Scan(
			&data,
			&r.Ingress,
			&r.Egress,
			&r.Counter,
			&r.IsIngress,
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

	return result, rows.Err()
}

/*
func (d *DataQuerier) runInserter() error {
	rows := make([]*Row, d.batchSize)
	args := make([]interface{}, 0, d.batchSize*5)
	ctx := context.Background()
	err := d.ensureTables(ctx)
	if err != nil {
		return err
	}
	for {
		row := <-d.Data
		if row == nil {
			break
		}
		rows[0] = row
		num_reads := 1
	loop:
		for ; num_reads < d.batchSize; num_reads++ {
			select {
			case row = <-d.Data:
				rows[num_reads] = row
				if row == nil {
					break loop
				}
			default:
				break loop
			}
		}
		//log.Debug("insert")
		d.insert(ctx, rows[:num_reads], args[:0])
	}
	return nil
}

func (d *DataInserter) ensureTables(ctx context.Context) error {
	_, err := d.pool.Exec(ctx, `
            CREATE TABLE IF NOT EXISTS buckets (
                time        TIMESTAMPTZ NOT NULL,
                time_window SMALLINT NOT NULL,
                data        BYTEA NOT NULL,
                ingress     SMALLINT NOT NULL,
                egress      SMALLINT
				counter		INTEGER
            );
        `)
	if err != nil {
		return err
	}

	return nil
}

func (d *DataInserter) insert(ctx context.Context, rows []*Row, args []interface{}) error {
	var sb strings.Builder
	sb.WriteString("INSERT INTO buckets (time, time_window, data, ingress, egress) VALUES")

	for i, r := range rows {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf("($%d,$%d,$%d,$%d,$%d)",
			i*5+1, i*5+2, i*5+3, i*5+4, i*5+5))
		args = append(args,
			r.Time,
			r.TimeWindow,
			r.Data[:],
			r.Ingress,
			r.Egress,
		)
	}
	_, err := d.pool.Exec(ctx, sb.String(), args...)
	if err != nil {
		return err
	}
	return nil
}
*/
