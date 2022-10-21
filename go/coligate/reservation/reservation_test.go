package reservation_test

import (
	"testing"
	"time"

	"github.com/scionproto/scion/go/coligate/reservation"
	"github.com/stretchr/testify/assert"
)

func TestReservationNotFound(t *testing.T) {
	storage := &reservation.ReservationStorage{}
	storage.InitStorage()
	res, found := storage.UseReservation("A", 0, time.Now())
	assert.False(t, found)
	assert.Nil(t, res)
}

func TestReservationVersionNotFound(t *testing.T) {
	storage := &reservation.ReservationStorage{}
	resmap := make(map[string]*reservation.Reservation)
	resvmap := make(map[uint8]*reservation.ReservationVersion)
	resvmap[0] = &reservation.ReservationVersion{
		Version:  0,
		Validity: time.Now().Add(1 * time.Minute),
	}

	resmap["A"] = &reservation.Reservation{
		ReservationId:   "A",
		Versions:        resvmap,
		ActiveVersionId: 0,
	}
	storage.InitStorageWithData(resmap)

	res, found := storage.UseReservation("A", 1, time.Now())
	assert.False(t, found)
	assert.Nil(t, res)
}

func TestActiveVersionIsProvidedVersion(t *testing.T) {
	storage := &reservation.ReservationStorage{}
	resmap := make(map[string]*reservation.Reservation)
	resvmap := make(map[uint8]*reservation.ReservationVersion)
	resvmap[0] = &reservation.ReservationVersion{
		Version:  0,
		Validity: time.Now().Add(1 * time.Minute),
	}

	resmap["A"] = &reservation.Reservation{
		ReservationId:   "A",
		Versions:        resvmap,
		ActiveVersionId: 0,
	}
	storage.InitStorageWithData(resmap)

	res, found := storage.UseReservation("A", 0, time.Now())
	assert.True(t, found)
	assert.Equal(t, uint8(0), res.ActiveVersionId)
}

func TestActiveVersionOlder(t *testing.T) {
	storage := &reservation.ReservationStorage{}
	resmap := make(map[string]*reservation.Reservation)
	resvmap := make(map[uint8]*reservation.ReservationVersion)
	resvmap[0] = &reservation.ReservationVersion{
		Version:  0,
		Validity: time.Now().Add(1 * time.Minute),
	}
	resvmap[1] = &reservation.ReservationVersion{
		Version:  1,
		Validity: time.Now().Add(2 * time.Minute),
	}

	resmap["A"] = &reservation.Reservation{
		ReservationId:   "A",
		Versions:        resvmap,
		ActiveVersionId: 0,
	}
	storage.InitStorageWithData(resmap)

	res, found := storage.UseReservation("A", 1, time.Now())
	assert.True(t, found)
	assert.Equal(t, uint8(1), res.ActiveVersionId)
	_, found = res.Versions[0]
	assert.False(t, found)

}

func TestActiveVersionNewer(t *testing.T) {
	storage := &reservation.ReservationStorage{}
	resmap := make(map[string]*reservation.Reservation)
	resvmap := make(map[uint8]*reservation.ReservationVersion)
	resvmap[0] = &reservation.ReservationVersion{
		Version:  0,
		Validity: time.Now().Add(2 * time.Minute),
	}
	resvmap[1] = &reservation.ReservationVersion{
		Version:  1,
		Validity: time.Now().Add(1 * time.Minute),
	}

	resmap["A"] = &reservation.Reservation{
		ReservationId:   "A",
		Versions:        resvmap,
		ActiveVersionId: 0,
	}
	storage.InitStorageWithData(resmap)
	_, found := storage.UseReservation("A", 1, time.Now())
	assert.False(t, found)
	_, found = resvmap[1]
	assert.False(t, found)
}

func TestPacketValidityIsChecked(t *testing.T) {
	storage := &reservation.ReservationStorage{}
	resmap := make(map[string]*reservation.Reservation)
	resvmap := make(map[uint8]*reservation.ReservationVersion)
	now := time.Now()
	resvmap[0] = &reservation.ReservationVersion{
		Version:  0,
		Validity: now,
	}

	resmap["A"] = &reservation.Reservation{
		ReservationId:   "A",
		Versions:        resvmap,
		ActiveVersionId: 0,
	}
	storage.InitStorageWithData(resmap)

	res, found := storage.UseReservation("A", 0, now)
	assert.True(t, found)
	assert.Equal(t, "A", res.ReservationId)
	res, found = storage.UseReservation("A", 0, now.Add(1*time.Second))
	assert.False(t, found)
	assert.Nil(t, res)
}
