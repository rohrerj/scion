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
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/scionproto/scion/pkg/log"
)

type DataInserter struct {
	Data      chan *Row
	batchSize int
	pool      *pgxpool.Pool
}

type Row struct {
	Time       time.Time
	TimeWindow int16
	Data       [32]byte
	Ingress    int16
	Egress     int16
}

func SetupDataInserter(ctx context.Context, channelSize int, batchSize int, connStr string) (*DataInserter, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, err
	}
	d := &DataInserter{
		Data:      make(chan *Row, channelSize),
		batchSize: batchSize,
		pool:      pool,
	}
	go func() {
		defer log.HandlePanic()
		err := d.runInserter()
		if err != nil {
			log.Error("Error while running db inserter", "err", err)
		}
	}()
	return d, nil
}

func (d *DataInserter) runInserter() error {
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
                egress      SMALLINT NOT NULL
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
