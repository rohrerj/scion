package reservation_test

import (
	"testing"
	"time"

	"github.com/scionproto/scion/go/coligate/reservation"
	"github.com/stretchr/testify/assert"
)

func TestIsReservationValid(t *testing.T) {
	storage := &reservation.ReservationStorage{}
	storage.InitStorage()

	now := time.Now()

	res, found := storage.IsReservationValid("A", now)
	assert.False(t, found)
	assert.Nil(t, res)

	storage.Update(&reservation.ReservationTask{
		ResId: "A",
		Reservation: &reservation.Reservation{
			ReservationId: "A",
			Version:       1,
			Validity:      now.Add(1 * time.Minute),
			Macs:          nil,
			Hops:          nil,
			BwCls:         0,
			Rlc:           0,
		},
	})
	res, found = storage.IsReservationValid("A", now)
	assert.True(t, found)
	assert.Equal(t, "A", res.ReservationId)
	assert.Equal(t, now.Add(1*time.Minute), res.Validity)

	res, found = storage.IsReservationValid("A", now.Add(1*time.Minute))
	assert.True(t, found)
	assert.Equal(t, "A", res.ReservationId)
	assert.Equal(t, now.Add(1*time.Minute), res.Validity)

	res, found = storage.IsReservationValid("A", now.Add(1*time.Minute+1))
	assert.False(t, found)
	assert.Nil(t, res)
}
