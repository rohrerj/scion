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
	Version       int
	Validity      time.Time
	Macs          [][]byte
	Hops          []HopField
	BwCls         uint8
	Rlc           uint8
}

type ReservationTask struct {
	Reservation   *Reservation
	ResId         string
	IsDeleteQuery bool
}

// initializes the reservation storage
func (store *ReservationStorage) InitStorage() {
	store.reservations = make(map[string]*Reservation)
}

// checks whether the reservation exists and is valid. If the reservation exists but is not valid anymore, it will be removed.
// If the reservation exists and is valid, the reservation is returned.
func (store *ReservationStorage) IsReservationValid(resId string, pktTime time.Time) (*Reservation, bool) {
	res, found := store.reservations[resId]
	if !found {
		return nil, false
	}
	if res.Validity.Sub(pktTime) < 0 {
		delete(store.reservations, resId)
		return nil, false
	}
	return res, true
}

// Replaces the stored reservation for that reservation ID with the reservation provided by the reservation task
func (store *ReservationStorage) Update(task *ReservationTask) {
	store.reservations[task.ResId] = task.Reservation
}

// Deletes a stored reservation by providing its reservation ID
func (store *ReservationStorage) Delete(task *ReservationTask) {
	delete(store.reservations, task.ResId)
}
