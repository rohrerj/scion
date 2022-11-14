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

package processing_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"

	proc "github.com/scionproto/scion/go/coligate/processing"
	"github.com/scionproto/scion/go/coligate/reservation"
)

func ErrGroupWait(e *errgroup.Group, duration time.Duration) error {
	c := make(chan struct{})
	var err error
	go func() {
		defer close(c)
		err = e.Wait()
	}()
	select {
	case <-c:
		return err
	case <-time.After(duration):
		return errors.New("Wait group did not finish in time")
	}
}

// Tests sequentially that write-read-repeat returns all reservations
// and that the channel is empty after the exit.
func TestCleanupRoutineSingleTaskSequentially(t *testing.T) {
	L := 10
	errGroup := &errgroup.Group{}
	c := &proc.Control{}
	cleanupChannel := c.CreateCleanupChannel(L)
	reservationChannels := c.CreateReservationChannels(1, L)
	now := time.Now()

	c.SetHasher([]byte("salt"))
	errGroup.Go(func() error {
		c.InitCleanupRoutine()
		return nil
	})

	for i := 0; i < L; i++ {
		cleanupChannel <- &reservation.ReservationTask{
			ResId:           "A" + fmt.Sprint(i),
			HighestValidity: now.Add(1 * time.Millisecond),
		}
		select {
		case task := <-reservationChannels[0]:
			assert.NotNil(t, task)
			assert.Equal(t, "A"+fmt.Sprint(i), task.ResId)
			assert.Equal(t, true, task.IsDeleteQuery)
		case <-time.After(1 * time.Second):
			assert.Fail(t, "reservation not deleted")
		}
	}

	c.Exit()
	assert.NoError(t, ErrGroupWait(errGroup, 1*time.Second))

	select {
	case task := <-reservationChannels[0]:
		assert.Fail(t, "cleanup routine returned unexpected value", "ResId", task.ResId)
	default:
	}
}

// Tests that the cleanup routine returns all reservations (in any order) once
// they are expired.
func TestCleanupRoutineBatchOfTasksSequentially(t *testing.T) {
	L := 10
	errGroup := &errgroup.Group{}
	c := &proc.Control{}
	cleanupChannel := c.CreateCleanupChannel(L)
	reservationChannels := c.CreateReservationChannels(1, L)

	c.SetHasher([]byte("salt"))
	errGroup.Go(func() error {
		c.InitCleanupRoutine()
		return nil
	})

	now := time.Now()
	for i := 0; i < L; i++ {
		cleanupChannel <- &reservation.ReservationTask{
			ResId:           "A" + fmt.Sprint(i),
			HighestValidity: now.Add(1 * time.Millisecond),
		}
	}
	exit := false
	reportedReservations := 0
	for !exit {
		select {
		case <-reservationChannels[0]:
			reportedReservations++
		case <-time.After(20 * time.Millisecond):
			exit = true
		}
	}
	assert.Equal(t, L, reportedReservations)
	c.Exit()
	assert.NoError(t, ErrGroupWait(errGroup, 1*time.Second))
}

// Tests that the validity of a currently stored reservation is
// extended if a new index arrives with longer validity
func TestCleanupRoutineSupersedeOld(t *testing.T) {
	L := 100
	errGroup := &errgroup.Group{}
	c := &proc.Control{}
	cleanupChannel := c.CreateCleanupChannel(L)
	reservationChannels := c.CreateReservationChannels(1, L)

	c.SetHasher([]byte("salt"))
	errGroup.Go(func() error {
		c.InitCleanupRoutine()
		return nil
	})
	now := time.Now()

	for i := 0; i < L; i++ {
		cleanupChannel <- &reservation.ReservationTask{
			ResId:           "A" + fmt.Sprint(i),
			HighestValidity: now.Add(10 * time.Millisecond),
		}
	}

	for i := 0; i < L; i++ {
		cleanupChannel <- &reservation.ReservationTask{
			ResId:           "A" + fmt.Sprint(i),
			HighestValidity: now.Add(20 * time.Millisecond),
		}
	}

	reportedReservations := 0
	exit := false
	for !exit {
		select {
		case task := <-reservationChannels[0]:
			if task.HighestValidity == now.Add(10*time.Millisecond) {
				continue
			}
			assert.Equal(t, now.Add(20*time.Millisecond), task.HighestValidity)
			reportedReservations++
		case <-time.After(40 * time.Millisecond):
			exit = true
		}
	}
	assert.Equal(t, L, reportedReservations)
	c.Exit()

	assert.NoError(t, ErrGroupWait(errGroup, 1*time.Second))
}
