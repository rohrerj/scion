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

package reservation_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/coligate/reservation"
)

func TestReservationNotFound(t *testing.T) {
	storage := &reservation.Storage{}
	storage.InitStorageWithData(nil)
	res, found := storage.UseReservation("A", 0, time.Now())
	assert.False(t, found)
	assert.Nil(t, res)
}

func TestReservationVersionNotFound(t *testing.T) {
	storage := &reservation.Storage{}
	resmap := make(map[string]*reservation.Reservation)
	resvmap := make(map[uint8]*reservation.ReservationIndex)
	resvmap[0] = &reservation.ReservationIndex{
		Index:    0,
		Validity: time.Now().Add(1 * time.Minute),
	}

	resmap["A"] = &reservation.Reservation{
		Id:            "A",
		Indices:       resvmap,
		ActiveIndexId: 0,
	}
	storage.InitStorageWithData(resmap)

	res, found := storage.UseReservation("A", 1, time.Now())
	assert.False(t, found)
	assert.Nil(t, res)
}

func TestActiveVersionIsProvidedVersion(t *testing.T) {
	storage := &reservation.Storage{}
	resmap := make(map[string]*reservation.Reservation)
	resvmap := make(map[uint8]*reservation.ReservationIndex)
	resvmap[0] = &reservation.ReservationIndex{
		Index:    0,
		Validity: time.Now().Add(1 * time.Minute),
	}

	resmap["A"] = &reservation.Reservation{
		Id:            "A",
		Indices:       resvmap,
		ActiveIndexId: 0,
	}
	storage.InitStorageWithData(resmap)

	res, found := storage.UseReservation("A", 0, time.Now())
	assert.True(t, found)
	assert.Equal(t, uint8(0), res.ActiveIndexId)
}

func TestActiveVersionOlder(t *testing.T) {
	storage := &reservation.Storage{}
	resmap := make(map[string]*reservation.Reservation)
	resvmap := make(map[uint8]*reservation.ReservationIndex)
	resvmap[0] = &reservation.ReservationIndex{
		Index:    0,
		Validity: time.Now().Add(1 * time.Minute),
	}
	resvmap[1] = &reservation.ReservationIndex{
		Index:    1,
		Validity: time.Now().Add(2 * time.Minute),
	}

	resmap["A"] = &reservation.Reservation{
		Id:            "A",
		Indices:       resvmap,
		ActiveIndexId: 0,
	}
	storage.InitStorageWithData(resmap)

	res, found := storage.UseReservation("A", 1, time.Now())
	assert.True(t, found)
	assert.Equal(t, uint8(1), res.ActiveIndexId)
	_, found = res.Indices[0]
	assert.False(t, found)

}

func TestActiveVersionNewer(t *testing.T) {
	storage := &reservation.Storage{}
	resmap := make(map[string]*reservation.Reservation)
	resvmap := make(map[uint8]*reservation.ReservationIndex)
	resvmap[0] = &reservation.ReservationIndex{
		Index:    0,
		Validity: time.Now().Add(2 * time.Minute),
	}
	resvmap[1] = &reservation.ReservationIndex{
		Index:    1,
		Validity: time.Now().Add(1 * time.Minute),
	}

	resmap["A"] = &reservation.Reservation{
		Id:            "A",
		Indices:       resvmap,
		ActiveIndexId: 0,
	}
	storage.InitStorageWithData(resmap)
	_, found := storage.UseReservation("A", 1, time.Now())
	assert.False(t, found)
	_, found = resvmap[1]
	assert.False(t, found)
}

func TestPacketValidityIsChecked(t *testing.T) {
	storage := &reservation.Storage{}
	resmap := make(map[string]*reservation.Reservation)
	resvmap := make(map[uint8]*reservation.ReservationIndex)
	now := time.Now()
	resvmap[0] = &reservation.ReservationIndex{
		Index:    0,
		Validity: now,
	}

	resmap["A"] = &reservation.Reservation{
		Id:            "A",
		Indices:       resvmap,
		ActiveIndexId: 0,
	}
	storage.InitStorageWithData(resmap)

	res, found := storage.UseReservation("A", 0, now)
	assert.True(t, found)
	assert.Equal(t, "A", res.Id)
	res, found = storage.UseReservation("A", 0, now.Add(1*time.Second))
	assert.False(t, found)
	assert.Nil(t, res)
}
