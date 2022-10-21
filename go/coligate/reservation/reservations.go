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
	ReservationId   string
	Hops            []HopField
	Rlc             uint8
	ActiveVersionId uint8
	Versions        map[uint8]*ReservationVersion
}
type ReservationVersion struct {
	Version  uint8
	Validity time.Time
	Macs     [][]byte
	BwCls    uint8
}

type ReservationTask struct {
	Reservation     *Reservation
	ResId           string
	IsDeleteQuery   bool
	HighestValidity time.Time //might be unset. depending on context
}

func (res *Reservation) Current() *ReservationVersion {
	ver, found := res.Versions[res.ActiveVersionId]
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
func (store *ReservationStorage) UseReservation(resId string, version uint8, pktTime time.Time) (*Reservation, bool) {
	res, found := store.reservations[resId]
	if !found {
		return nil, false
	}
	ver, found := res.Versions[version]
	if !found {
		return nil, false
	}
	defer res.deleteOlderVersions()

	if res.ActiveVersionId != version {
		activeVer, found := res.Versions[res.ActiveVersionId]
		if found && ver.Validity.Sub(activeVer.Validity) < 0 { //active version exists but has longer validity than provided version
			return nil, false
		} else {
			res.ActiveVersionId = version
		}
	}

	if ver.Validity.Sub(pktTime) >= 0 {
		return res, true
	}

	return nil, false
}

// Merges (overwrites if exists in both) all provided reservation versions with the currently stored versions.
// Creates a new entry if no reservation exists.
func (store *ReservationStorage) Update(task *ReservationTask) {
	res, found := store.reservations[task.ResId]
	if found {
		for versioNumber, reservationVersion := range task.Reservation.Versions {
			res.Versions[versioNumber] = reservationVersion
		}
	} else {
		store.reservations[task.ResId] = task.Reservation
	}
}

// Compares the validity of all versions with the active version and deletes all versions whose validity is behind the active version.
// If the active version is not valid, it will do the comparison with the current time.
func (res *Reservation) deleteOlderVersions() {
	v, found := res.Versions[res.ActiveVersionId]
	var t time.Time
	if found {
		t = v.Validity
	} else {
		t = time.Now()
	}
	for _, ver := range res.Versions {
		if ver.Validity.Sub(t) < 0 {
			delete(res.Versions, uint8(ver.Version))
		}
	}
}

// Deletes a stored reservation by providing its reservation ID
func (store *ReservationStorage) Delete(task *ReservationTask) {
	delete(store.reservations, task.ResId)
}
