package reservation

import (
	"time"
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
	Version  uint8
	Validity time.Time
	Macs     [][]byte
	BwCls    uint8
}

type ReservationTask struct {
	Reservation     *Reservation
	ResId           string
	IsDeleteQuery   bool
	HighestValidity time.Time //The validity of the longest (but possible not active) reservation index.
}

// Returns the active reservation index. If the active reservation id is not valid (anymore) nil is returned.
func (res *Reservation) Current() *ReservationIndex {
	ver, found := res.Indices[res.ActiveIndexId]
	if !found {
		return nil
	}
	return ver
}

// initializes the reservation storage
func (store *ReservationStorage) InitStorage() {
	store.reservations = make(map[string]*Reservation)
}

func (store *ReservationStorage) InitStorageWithData(data map[string]*Reservation) {
	store.reservations = data
}

// Checks whether the reservation exists and is valid. If the reservation exists but is not valid anymore, it will be removed.
// If the reservation exists and is valid, the reservation is returned.
func (store *ReservationStorage) UseReservation(resId string, providexIndex uint8, pktTime time.Time) (*Reservation, bool) {
	res, found := store.reservations[resId]
	if !found {
		return nil, false
	}
	index, found := res.Indices[providexIndex]
	if !found {
		return nil, false
	}
	defer res.deleteOlderIndices()

	if res.ActiveIndexId != providexIndex {
		activeVer, found := res.Indices[res.ActiveIndexId]
		if found && index.Validity.Sub(activeVer.Validity) < 0 { //active version exists but has longer validity than provided version
			return nil, false
		} else {
			res.ActiveIndexId = providexIndex
		}
	}

	if index.Validity.Sub(pktTime) >= 0 {
		return res, true
	}

	return nil, false
}

// Merges (overwrites if exists in both) all provided reservation indices with the currently stored indices.
// Creates a new entry if no reservation exists.
func (store *ReservationStorage) Update(task *ReservationTask) {
	res, found := store.reservations[task.ResId]
	if found {
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
		if ver.Validity.Sub(t) < 0 {
			delete(res.Indices, uint8(ver.Version))
		}
	}
}

// Deletes a stored reservation by providing its reservation ID
func (store *ReservationStorage) Delete(task *ReservationTask) {
	delete(store.reservations, task.ResId)
}
