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
	"fmt"
	"testing"
	"time"

	proc "github.com/scionproto/scion/go/coligate/processing"
	"github.com/scionproto/scion/go/coligate/reservation"
	common "github.com/scionproto/scion/go/pkg/coligate"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
)

func TestCleanupRoutineSingleTaskSequentially(t *testing.T) {
	L := 10
	errGroup := &errgroup.Group{}
	c := &proc.Control{}
	cleanupChannel := c.CreateCleanupChannel(L)
	reservationChannels := c.CreateReservationChannels(1, L)
	now := time.Now()

	c.InitCleanupRoutine(errGroup, common.CreateFnv1aHasher("salt"))
	for i := 0; i < L; i++ {
		cleanupChannel <- &reservation.ReservationTask{
			ResId:           "A" + fmt.Sprint(i),
			HighestValidity: now.Add(1 * time.Millisecond),
		}
		task := <-reservationChannels[0]
		assert.NotNil(t, task)
		assert.Equal(t, "A"+fmt.Sprint(i), task.ResId)
		assert.Equal(t, true, task.IsDeleteQuery)
	}
	select {
	case task := <-reservationChannels[0]:
		assert.Fail(t, "cleanup routine returned unexpected value", "ResId", task.ResId)
	case <-time.After(1 * time.Second):
	}

	c.Exit()
	errGroup.Wait()
}

func TestCleanupRoutineBatchOfTasksSequentially(t *testing.T) {
	L := 10
	errGroup := &errgroup.Group{}
	c := &proc.Control{}
	cleanupChannel := c.CreateCleanupChannel(L)
	reservationChannels := c.CreateReservationChannels(1, L)

	c.InitCleanupRoutine(errGroup, common.CreateFnv1aHasher("salt"))

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
		case <-time.After(1 * time.Second):
			exit = true
		}
	}
	assert.Equal(t, L, reportedReservations)
	c.Exit()
	errGroup.Wait()
}

func TestCleanupRoutineParallel(t *testing.T) {
	L := 100
	errGroup := &errgroup.Group{}
	c := &proc.Control{}
	cleanupChannel := c.CreateCleanupChannel(L)
	reservationChannels := c.CreateReservationChannels(1, L)

	c.InitCleanupRoutine(errGroup, common.CreateFnv1aHasher("salt"))
	now := time.Now()

	errGroup.Go(func() error {
		for i := 0; i < L; i++ {
			cleanupChannel <- &reservation.ReservationTask{
				ResId:           "A" + fmt.Sprint(i),
				HighestValidity: now.Add(1 * time.Second),
			}
		}

		return nil
	})

	errGroup.Go(func() error {
		for i := L - 1; i >= 0; i-- {
			cleanupChannel <- &reservation.ReservationTask{
				ResId:           "A" + fmt.Sprint(i),
				HighestValidity: now.Add(2 * time.Second),
			}
		}
		return nil
	})

	reportedReservations := 0
	exit := false
	for !exit {
		select {
		case task := <-reservationChannels[0]:
			assert.Equal(t, now.Add(2*time.Second), task.HighestValidity)
			reportedReservations++
		case <-time.After(3 * time.Second):
			exit = true
		}
	}
	assert.Equal(t, L, reportedReservations)
	c.Exit()

	errGroup.Wait()
}
