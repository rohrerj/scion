// Copyright 2022 ETH Zurich
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

package test

import (
	"fmt"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/co/reservation/e2e"
	"github.com/scionproto/scion/go/co/reservation/test"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

// ReservationMod allows the configuration of reservations via function calls, aka
// functional options.
// As this signature is used only in tests, it doesn't return an error: it assumes that
// the function implementing the option will panic if error.
type ReservationMod func(*e2e.Reservation) *e2e.Reservation

// NewRsv creates a reservation configured via functional options.
func NewRsv(mods ...ReservationMod) *e2e.Reservation {
	return ModRsv(&e2e.Reservation{}, mods...)
}

// ModRsv simply modifies an existing reservation via functional options.
func ModRsv(rsv *e2e.Reservation, mods ...ReservationMod) *e2e.Reservation {
	for _, mod := range mods {
		rsv = mod(rsv)
	}
	return rsv
}

// WithID sets the ID specified with as and suffix to the reservation.
func WithID(as, suffix string) ReservationMod {
	as_ := xtest.MustParseAS(as)
	id, err := reservation.NewID(as_, xtest.MustParseHexString(suffix))
	if err != nil {
		panic(err)
	}
	if !id.IsE2EID() {
		panic(fmt.Errorf("not an EER ID: %s", id.String()))
	}
	return func(rsv *e2e.Reservation) *e2e.Reservation {
		rsv.ID = *id
		return rsv
	}
}

func WithPath(path ...interface{}) ReservationMod {
	snetPath := test.NewSnetPath(path...)
	steps, err := base.StepsFromSnet(snetPath)
	if err != nil {
		panic(err)
	}
	return func(rsv *e2e.Reservation) *e2e.Reservation {
		rsv.Steps = steps
		return rsv
	}
}

func WithCurrentStep(currentStep int) ReservationMod {
	return func(rsv *e2e.Reservation) *e2e.Reservation {
		rsv.CurrentStep = currentStep
		return rsv
	}
}

// IndexMod allows the creation of indices with parameters via functional configuration.
// This type doesn't return an error, thus assumes the functional option will panic or ignore
// the error.
type IndexMod func(*e2e.Index)

// AddIndex adds a new index, modified via functional options, to the reservation.
func AddIndex(idx int, mods ...IndexMod) ReservationMod {
	return func(rsv *e2e.Reservation) *e2e.Reservation {
		expTime := util.SecsToTime(0)
		if rsv.Indices.Len() > 0 {
			expTime = rsv.Indices.GetExpiration(rsv.Indices.Len() - 1)
		}
		idx, err := rsv.NewIndex(expTime, 0)
		if err != nil {
			panic(err)
		}
		index := rsv.Index(idx)
		// set the token's path type to something valid
		index.Token.PathType = reservation.CorePath
		for _, mod := range mods {
			mod(index)
		}
		return rsv
	}
}

// ModIndex applies the functional options to the index specified.
func ModIndex(idx reservation.IndexNumber, mods ...IndexMod) ReservationMod {
	return func(rsv *e2e.Reservation) *e2e.Reservation {
		index := rsv.Index(idx)
		if index == nil {
			panic(fmt.Errorf("index is nil. idx = %d, len = %d", idx, rsv.Indices.Len()))
		}
		for _, mod := range mods {
			mod(index)
		}
		return rsv
	}
}

// WithBW changes the min, max and/or alloc BW if their values are > 0.
func WithBW(allocBW int) IndexMod {
	return func(index *e2e.Index) {
		index.AllocBW = reservation.BWCls(allocBW)
		if index.Token != nil {
			index.Token.BWCls = reservation.BWCls(allocBW)
		}
	}
}

// WithExpiration sets the expiration to the index (and its token).
func WithExpiration(exp time.Time) IndexMod {
	return func(index *e2e.Index) {
		index.Expiration = exp
		index.Token.ExpirationTick = reservation.TickFromTime(exp)
	}
}
