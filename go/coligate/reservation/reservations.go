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

package reservation

import (
	"time"

	"github.com/scionproto/scion/go/lib/log"
)

type ReservationStorage struct {
	reservations map[string]*Reservation
}
type HopField struct {
	IngressId uint16
	EgressId  uint16
}
type Reservation struct {
	ReservationId string
	Hops          []HopField
	Rlc           uint8
	ActiveIndexId uint8
	Indices       map[uint8]*ReservationIndex
}
type ReservationIndex struct {
	Index    uint8
	Validity time.Time
	Macs     [][]byte
	BwCls    uint8
}

type ReservationTask struct {
	Reservation       *Reservation
	ResId             string
	IsDeleteQuery     bool
	HighestValidity   time.Time //The validity of the longest (but possible not active) reservation index.
	IsInitReservation bool      //Is used to signalize the reservation cleanup routine to fast progress and not re-check other reservations
}

// Current returns the active reservation index. If the active reservation index does not exist (anymore) nil is returned.
func (res *Reservation) Current() *ReservationIndex {
	ver, found := res.Indices[res.ActiveIndexId]
	if !found {
		return nil
	}
	return ver
}

// InitStorageWithData initializes the reservation storage
func (store *ReservationStorage) InitStorageWithData(data map[string]*Reservation) {
	if data == nil {
		store.reservations = make(map[string]*Reservation)
	} else {
		store.reservations = data
	}
}

// UseReservation checks whether the reservation index exists and is valid. If the reservation exists but contains no longer valid indices,
// they will be removed. If the reservation index exists and is valid, the reservation is returned.
func (store *ReservationStorage) UseReservation(resId string, providedIndex uint8, pktTime time.Time) (*Reservation, bool) {
	log.Debug("use resId", "resId", resId)
	res, found := store.reservations[resId]
	if !found {
		log.Debug("reservation not found")
		return nil, false
	}
	index, found := res.Indices[providedIndex]
	if !found {
		log.Debug("reservation index not found")
		return nil, false
	}
	defer res.deleteOlderIndices()

	if res.ActiveIndexId != providedIndex {
		activeVer, found := res.Indices[res.ActiveIndexId]
		if found && activeVer.Validity.After(index.Validity) { //active index exists but has longer validity than provided index
			return nil, false
		} else {
			res.ActiveIndexId = providedIndex
		}
	}

	if !pktTime.After(index.Validity) {
		return res, true
	}

	return nil, false
}

// Update merges (overwrites if exists in both) all provided reservation indices with the currently stored indices.
// Creates a new entry if no reservation exists.
func (store *ReservationStorage) Update(task *ReservationTask) {
	res, found := store.reservations[task.ResId]
	if found {
		defer res.deleteOlderIndices()
		for indexNumber, reservationIndex := range task.Reservation.Indices {
			res.Indices[indexNumber] = reservationIndex
		}
	} else {
		store.reservations[task.ResId] = task.Reservation
	}
}

// Compares the validity of all indices with the active index and deletes all indices whose validity is behind the active index.
// If the active index is not valid, it will do the comparison with the current time.
func (res *Reservation) deleteOlderIndices() {
	v, found := res.Indices[res.ActiveIndexId]
	var t time.Time
	if found {
		t = v.Validity
	} else {
		t = time.Now()
	}
	for _, ver := range res.Indices {
		if ver.Validity.Before(t) {
			delete(res.Indices, uint8(ver.Index))
		}
	}
}

// Delete deletes a stored reservation with its indicies by providing its reservation ID.
func (store *ReservationStorage) Delete(task *ReservationTask) {
	delete(store.reservations, task.ResId)
}
