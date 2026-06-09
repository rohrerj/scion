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
	"database/sql"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

type AssetQuery struct {
	OwnerId              *int64
	IA                   *uint64
	Ingress              *uint32
	Egress               *uint32
	MinRequiredBandwidth *uint64
	StartsAt             *string
	StopsAt              *string
	Price                *uint64
}
type ReservationQuery struct {
	OwnerId  int64
	IA       *uint64
	Ingress  *uint32
	Egress   *uint32
	StartsAt *string
	StopsAt  *string
}

type DBReservation struct {
	ID        int64
	IA        addr.IA
	Ingress   int64
	Egress    int64
	Bandwidth int64
	StartsAt  time.Time
	StopsAt   time.Time
	OwnerId   int64
	Key       string
}

type DBAsset struct {
	ID              int64
	OwnerId         sql.NullInt64
	IA              addr.IA
	Bandwidth       uint64
	BandwidthMin    uint64
	StartAt         time.Time
	StopsAt         time.Time
	Price           uint64
	TimeGranularity uint64
	TimeMinDuration uint64
	IfIdIngress     sql.NullInt64
	IfIdEgress      sql.NullInt64
}

type DBUser struct {
	ID           int64
	Name         string
	Balance      int64
	PasswordHash string
}

type DBASUser struct {
	IA uint64
}
