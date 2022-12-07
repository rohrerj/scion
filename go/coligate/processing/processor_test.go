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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/ipv4"
	"golang.org/x/sync/errgroup"

	proc "github.com/scionproto/scion/go/coligate/processing"
	"github.com/scionproto/scion/go/coligate/storage"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/slayers"
	colipath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
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

var coligateMetrics *proc.ColigateMetrics = proc.InitializeMetrics()

// Tests sequentially that write-read-repeat returns all reservations
// and that the channel is empty after the exit.
func TestCleanupRoutineSingleTaskSequentially(t *testing.T) {
	L := 10
	errGroup := &errgroup.Group{}
	c := &proc.Processor{}
	c.SetMetrics(coligateMetrics)
	cleanupChannel := c.CreateCleanupChannel(L)
	reservationDeletionChannels := c.CreateControlDeletionChannels(1, L)
	c.SetNumWorkers(1)
	now := time.Now()

	c.SetHasher([]byte("salt"))
	errGroup.Go(func() error {
		c.InitCleanupRoutine()
		return nil
	})

	for i := 0; i < L; i++ {
		cleanupChannel <- &storage.UpdateTask{
			Reservation: &storage.Reservation{
				Id: "A" + fmt.Sprint(i),
			},
			HighestValidity: now.Add(1 * time.Millisecond),
		}
		select {
		case task := <-reservationDeletionChannels[0]:
			assert.NotNil(t, task)
			assert.IsType(t, &storage.DeletionTask{}, task)
			assert.Equal(t, "A"+fmt.Sprint(i), task.ResId)
		case <-time.After(1 * time.Second):
			assert.Fail(t, "reservation not deleted")
		}
	}

	c.Shutdown()
	assert.NoError(t, ErrGroupWait(errGroup, 1*time.Second))

	select {
	case task := <-reservationDeletionChannels[0]:
		assert.Nil(t, task)
	default:
	}
}

// Tests that the cleanup routine returns all reservations (in any order) once
// they are expired.
func TestCleanupRoutineBatchOfTasksSequentially(t *testing.T) {
	L := 10
	errGroup := &errgroup.Group{}
	c := &proc.Processor{}
	c.SetMetrics(coligateMetrics)
	cleanupChannel := c.CreateCleanupChannel(L)
	reservationDeletionChannels := c.CreateControlDeletionChannels(1, L)
	c.SetNumWorkers(1)

	c.SetHasher([]byte("salt"))
	errGroup.Go(func() error {
		c.InitCleanupRoutine()
		return nil
	})

	now := time.Now()
	for i := 0; i < L; i++ {
		cleanupChannel <- &storage.UpdateTask{
			Reservation: &storage.Reservation{
				Id: "A" + fmt.Sprint(i),
			},
			HighestValidity: now.Add(1 * time.Millisecond),
		}
	}
	exit := false
	reportedReservations := 0
	for !exit {
		select {
		case <-reservationDeletionChannels[0]:
			reportedReservations++
		case <-time.After(20 * time.Millisecond):
			exit = true
		}
	}
	assert.Equal(t, L, reportedReservations)
	c.Shutdown()
	assert.NoError(t, ErrGroupWait(errGroup, 1*time.Second))
}

// Tests that the validity of a currently stored reservation is
// extended if a new index arrives with longer validity
func TestCleanupRoutineSupersedeOld(t *testing.T) {
	L := 100
	errGroup := &errgroup.Group{}
	c := &proc.Processor{}
	c.SetMetrics(coligateMetrics)
	cleanupChannel := c.CreateCleanupChannel(L)
	reservationDeletionChannels := c.CreateControlDeletionChannels(1, L)
	c.SetNumWorkers(1)

	c.SetHasher([]byte("salt"))
	errGroup.Go(func() error {
		c.InitCleanupRoutine()
		return nil
	})
	now := time.Now()

	for i := 0; i < L; i++ {
		cleanupChannel <- &storage.UpdateTask{
			Reservation: &storage.Reservation{
				Id: "A" + fmt.Sprint(i),
			},
			HighestValidity: now.Add(10 * time.Millisecond),
		}
	}

	for i := 0; i < L; i++ {
		cleanupChannel <- &storage.UpdateTask{
			Reservation: &storage.Reservation{
				Id: "A" + fmt.Sprint(i),
			},
			HighestValidity: now.Add(20 * time.Millisecond),
		}
	}

	reportedReservations := 0
	exit := false
	for !exit {
		select {
		case task := <-reservationDeletionChannels[0]:
			assert.IsType(t, &storage.DeletionTask{}, task)
			reportedReservations++
		case <-time.After(40 * time.Millisecond):
			exit = true
		}
	}
	assert.Equal(t, L, reportedReservations)
	c.Shutdown()

	assert.NoError(t, ErrGroupWait(errGroup, 1*time.Second))
}

func BenchmarkWorker(b *testing.B) {
	c := &proc.Processor{}
	c.SetMetrics(coligateMetrics)
	updateChannels := c.CreateControlUpdateChannels(1, 1000)
	c.CreateControlDeletionChannels(1, 1)
	dataChannels := c.CreateDataChannels(1, 1000)
	errGroup := &errgroup.Group{}
	errGroup.Go(func() error {
		return c.WorkerReceiveEntry(getColigateConfiguration(), 0, 1, addr.MustIAFrom(1, 1).AS())
	})

	borderRouterConnection := make(map[uint16]*ipv4.PacketConn)
	borderRouterAddr, err := net.ResolveUDPAddr("udp", "localhost:30000")
	if err != nil {
		b.Error(err)
	}
	conn, _ := net.DialUDP("udp", nil, borderRouterAddr)
	borderRouterConnection[uint16(2)] = ipv4.NewPacketConn(conn)
	c.SetBorderRouterConnections(borderRouterConnection)
	now := time.Now()
	updateChannels[0] <- &storage.UpdateTask{
		Reservation: &storage.Reservation{
			Id: string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
			Indices: map[uint8]*storage.ReservationIndex{
				1: {
					Index:    0,
					Validity: now.Add(12 * time.Second),
					Sigmas: [][]byte{
						{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
						{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1},
						{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2},
						{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3},
						{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4},
						{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5},
					},
					BwCls: 60,
				},
			},
			Hops: []storage.HopField{
				{
					IngressId: 1,
					EgressId:  2,
				},
				{
					IngressId: 3,
					EgressId:  4,
				},
				{
					IngressId: 5,
					EgressId:  6,
				},
				{
					IngressId: 7,
					EgressId:  8,
				},
				{
					IngressId: 9,
					EgressId:  10,
				},
				{
					IngressId: 11,
					EgressId:  12,
				},
			},
		},
	}
	defaultPkt := &proc.DataPacket{
		PktArrivalTime: time.Now(),
		ScionLayer: &slayers.SCION{
			PathType: 4,
			SrcIA:    addr.MustIAFrom(1, 1),
		},
		ColibriPath: &colipath.ColibriPath{
			InfoField: &colipath.InfoField{
				Ver:         1,
				ResIdSuffix: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
				BwCls:       60,
				ExpTick:     uint32(now.Add(12*time.Second).Unix() / 4),
			},
			HopFields: []*colipath.HopField{
				{
					IngressId: 1,
					EgressId:  2,
					Mac:       make([]byte, 4),
				},
				{
					IngressId: 3,
					EgressId:  4,
					Mac:       make([]byte, 4),
				},
				{
					IngressId: 5,
					EgressId:  6,
					Mac:       make([]byte, 4),
				},
				{
					IngressId: 7,
					EgressId:  8,
					Mac:       make([]byte, 4),
				},
				{
					IngressId: 9,
					EgressId:  10,
					Mac:       make([]byte, 4),
				},
				{
					IngressId: 11,
					EgressId:  12,
					Mac:       make([]byte, 4),
				},
			},
		},
		RawPacket: make([]byte, 400),
	}
	time.Sleep(1 * time.Millisecond)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dataChannels[0] <- defaultPkt.Parse()
	}
	dataChannels[0] <- nil
	errGroup.Wait()
}
