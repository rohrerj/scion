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
	"encoding/binary"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

type AssetQuery struct {
	OwnerId              *int64
	IA                   *addr.IA
	Ingress              *uint32
	Egress               *uint32
	MinRequiredBandwidth *uint64
	StartsAt             *string
	StopsAt              *string
	Price                *uint64
}

type UsedReservationsQuery struct {
	IA       addr.IA
	StartsAt string
	StopsAt  string
}

type UsedReservation struct {
	Id       uint32
	StartsAt time.Time
	StopsAt  time.Time
}

type RedemptionDelegation struct {
	IA                 addr.IA
	Expiration         time.Time
	ReservationIdLimit uint32
	Key                []byte
	Encodings          []byte
}

type ReservationQuery struct {
	OwnerId  int64
	IA       *addr.IA
	Ingress  *uint32
	Egress   *uint32
	StartsAt *string
	StopsAt  *string
}
type StatisticsQuery struct {
	IA          addr.IA
	WindowStart string
	WindowEnd   string
	Ingress     *uint32
	Egress      *uint32
}
type DBStat struct {
	Price     int64
	Bandwidth int64
	StartsAt  time.Time
	StopsAt   time.Time
	OwnerId   sql.NullInt64
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
	Key       []byte
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
	TokenVersion int64
}

type DBASUser struct {
	IA           addr.IA
	TokenVersion int64
	Balance      int64
}

func (r *RedemptionDelegation) EncodingsToInts() []uint64 {
	if len(r.Encodings)%8 != 0 {
		panic("invalid data length")
	}
	nums := make([]uint64, len(r.Encodings)/8)
	for i := range nums {
		nums[i] = binary.LittleEndian.Uint64(r.Encodings[i*8:])
	}
	return nums
}

func (r *RedemptionDelegation) EncodeInts(nums []uint64) {
	buf := make([]byte, len(nums)*8)
	for i, n := range nums {
		binary.LittleEndian.PutUint64(buf[i*8:], n)
	}
	r.Encodings = buf
}
