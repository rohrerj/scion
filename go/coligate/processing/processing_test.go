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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/coligate/processing"
	"github.com/scionproto/scion/go/coligate/reservation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/pkg/coligate/config"
)

func getColigateConfiguration() *config.ColigateConfig {
	cfg := &config.ColigateConfig{
		NumBitsForGatewayId:        1,
		NumBitsForWorkerId:         8,
		NumBitsForPerWorkerCounter: 23,
		NumWorkers:                 8,
		MaxQueueSizePerWorker:      256,
		Salt:                       "",
		ColibriGatewayID:           1,
	}
	return cfg
}

// TestMasking tests that the coreIdCounter is correctly assigned in InitWorker depending on
// the number of bits for the GatewayId, WorkerId, PerWorkerCounter.
func TestMasking(t *testing.T) {
	worker := processing.NewWorker(getColigateConfiguration(), 1, 1)
	expectedInitialValue := uint32(2147483648 + 8388608) //2^31 + 2^23
	assert.Equal(t, expectedInitialValue, worker.CoreIdCounter)

	worker.CoreIdCounter = worker.InitialCoreIdCounter | (worker.CoreIdCounter+1)%(1<<worker.NumCounterBits)
	assert.Equal(t, expectedInitialValue+1, worker.CoreIdCounter)

	worker.CoreIdCounter = worker.InitialCoreIdCounter | (worker.CoreIdCounter+1)%(1<<worker.NumCounterBits)
	assert.Equal(t, expectedInitialValue+2, worker.CoreIdCounter)

	worker.CoreIdCounter = expectedInitialValue + 8388607 //+ 2^23 -1
	worker.CoreIdCounter = worker.InitialCoreIdCounter | (worker.CoreIdCounter+1)%(1<<worker.NumCounterBits)
	assert.Equal(t, expectedInitialValue, worker.CoreIdCounter)
}

func TestHandleReservationTask(t *testing.T) {
	worker := processing.NewWorker(getColigateConfiguration(), 1, 1)
	reservations := make(map[string]*reservation.Reservation)
	worker.Storage.InitStorageWithData(reservations)
	var startTime = time.Now()

	//test that sending a delete query for a non existing reservation
	//does not create an error
	err := worker.HandleReservationTask(&reservation.ReservationTask{
		IsDeleteQuery: true,
		ResId:         "A",
	})
	assert.NoError(t, err)
	assert.Equal(t, 0, len(reservations))

	//test that a new reservation was stored
	err = worker.HandleReservationTask(&reservation.ReservationTask{
		ResId:           "A",
		HighestValidity: startTime.Add(1 * time.Second),
		Reservation: &reservation.Reservation{
			ReservationId: "A",
			Indices: map[uint8]*reservation.ReservationIndex{
				0: {
					Index:    0,
					Validity: startTime.Add(1 * time.Second),
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(reservations))
	assert.Equal(t, 1, len(reservations["A"].Indices))
	assert.NotNil(t, reservations["A"].Indices[0])

	//test that an older index does not get deleted if it is still valid and no active index
	//exists when updating
	err = worker.HandleReservationTask(&reservation.ReservationTask{
		ResId:           "A",
		HighestValidity: startTime.Add(2 * time.Second),
		Reservation: &reservation.Reservation{
			ReservationId: "A",
			Indices: map[uint8]*reservation.ReservationIndex{
				1: {
					Index:    0,
					Validity: startTime.Add(2 * time.Second),
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(reservations))
	assert.Equal(t, 2, len(reservations["A"].Indices))
	assert.NotNil(t, reservations["A"].Indices[0])
	assert.NotNil(t, reservations["A"].Indices[1])

	//now we activate index 1 and call again update for a new index with the same expiration time as index 1.
	//Now we test that index 0 is removed and 1 and 2 still exist.
	reservations["A"].ActiveIndexId = 1
	err = worker.HandleReservationTask(&reservation.ReservationTask{
		ResId:           "A",
		HighestValidity: startTime.Add(2 * time.Second),
		Reservation: &reservation.Reservation{
			ReservationId: "A",
			Indices: map[uint8]*reservation.ReservationIndex{
				2: {
					Index:    0,
					Validity: startTime.Add(2 * time.Second),
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(reservations))
	assert.Equal(t, 2, len(reservations["A"].Indices))
	assert.Nil(t, reservations["A"].Indices[0])
	assert.NotNil(t, reservations["A"].Indices[1])
	assert.NotNil(t, reservations["A"].Indices[2])

	//now we execute a delete query to delete the entire reservation
	err = worker.HandleReservationTask(&reservation.ReservationTask{
		IsDeleteQuery: true,
		ResId:         "A",
	})
	assert.NoError(t, err)
	assert.Equal(t, 0, len(reservations))
}

func TestValidate(t *testing.T) {
	type entry struct {
		proc    processing.DataPacket
		success bool
	}

	type test struct {
		name     string
		entries  []entry
		resStore map[string]*reservation.Reservation
	}
	worker := processing.NewWorker(getColigateConfiguration(), 1, 1)

	var startTime = time.Unix(0, 0)

	tests := []test{
		{
			name: "TestValidateCFlagIsSet",
			entries: []entry{
				{
					proc: processing.DataPacket{
						PktArrivalTime: startTime,
						ColibriPath: &colibri.ColibriPath{
							InfoField: &colibri.InfoField{
								C: true,
							},
						},
					},
					success: false,
				},
			},
		},
		{
			name: "TestValidateSFlagIsSet",
			entries: []entry{
				{
					proc: processing.DataPacket{
						PktArrivalTime: startTime,
						ColibriPath: &colibri.ColibriPath{
							InfoField: &colibri.InfoField{
								S: true,
							},
						},
					},
					success: false,
				},
			},
		},
		{
			name: "TestValidateReservationDoesNotExist",
			entries: []entry{
				{
					proc: processing.DataPacket{
						PktArrivalTime: startTime,
						ColibriPath: &colibri.ColibriPath{
							InfoField: &colibri.InfoField{
								ResIdSuffix: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
							},
						},
						ScionLayer: &slayers.SCION{
							SrcIA: addr.MustIAFrom(1, 1),
						},
					},
					success: false,
				},
			},
		},
		{
			name: "TestValidateInvalidNumberOfHopfields",
			resStore: map[string]*reservation.Reservation{
				string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}): {
					ReservationId: string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
					Hops:          make([]reservation.HopField, 1),
					ActiveIndexId: 0,
					Indices: map[uint8]*reservation.ReservationIndex{
						0: {
							Index:    0,
							Validity: startTime.Add(1),
							BwCls:    1,
							Macs:     make([][]byte, 1),
						},
					},
				},
			},
			entries: []entry{
				{
					proc: processing.DataPacket{
						PktArrivalTime: startTime,
						ColibriPath: &colibri.ColibriPath{
							InfoField: &colibri.InfoField{
								ResIdSuffix: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
							},
						},
						ScionLayer: &slayers.SCION{
							SrcIA: addr.MustIAFrom(1, 1),
						},
					},
					success: false,
				},
			},
		},
		{
			name: "TestValidateSFlagIsSet",
			entries: []entry{
				{
					proc: processing.DataPacket{
						PktArrivalTime: startTime,
						ColibriPath: &colibri.ColibriPath{
							InfoField: &colibri.InfoField{
								S: true,
							},
						},
					},
					success: false,
				},
			},
		},
		{
			name: "TestValidateReservationDoesNotExist",
			entries: []entry{
				{
					proc: processing.DataPacket{
						PktArrivalTime: startTime,
						ColibriPath: &colibri.ColibriPath{
							InfoField: &colibri.InfoField{
								ResIdSuffix: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
							},
						},
						ScionLayer: &slayers.SCION{
							SrcIA: addr.MustIAFrom(1, 1),
						},
					},
					success: false,
				},
			},
		},
		{
			name: "TestValidateAllValid",
			resStore: map[string]*reservation.Reservation{
				string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}): {
					ReservationId: string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
					Hops:          make([]reservation.HopField, 1),
					ActiveIndexId: 0,
					Indices: map[uint8]*reservation.ReservationIndex{
						0: {
							Index:    0,
							Validity: startTime.Add(1),
							BwCls:    1,
							Macs:     make([][]byte, 1),
						},
					},
				},
			},
			entries: []entry{
				{
					proc: processing.DataPacket{
						PktArrivalTime: startTime,
						ColibriPath: &colibri.ColibriPath{
							InfoField: &colibri.InfoField{
								ResIdSuffix: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
							},
							HopFields: make([]*colibri.HopField, 1),
						},
						ScionLayer: &slayers.SCION{
							SrcIA: addr.MustIAFrom(1, 1),
						},
					},
					success: true,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			worker.Storage.InitStorageWithData(tc.resStore)
			for _, en := range tc.entries {
				err := worker.Validate(&en.proc)
				assert.True(t, (err == nil && en.success) || (err != nil && !en.success))
			}
		})
	}
}

func TestPerformTrafficMonitoring(t *testing.T) {
	type entry struct {
		proc    processing.DataPacket
		success bool
	}

	type test struct {
		name    string
		entries []entry
	}
	worker := processing.NewWorker(getColigateConfiguration(), 1, 1)

	var startTime = time.Unix(0, 0)

	tests := []test{
		{
			name: "TestPerformTrafficMonitoringOnePacketFullBandwidth",
			entries: []entry{
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 16384),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
							},
						},
					},
					success: true,
				},
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 1),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
							},
						},
					},
					success: false,
				},
			},
		},
		{
			name: "TestPerformTrafficMonitoringSeveralPacketsTotalFullBandwidth",
			entries: []entry{
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 4096),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
							},
						},
					},
					success: true,
				},
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 4096),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
							},
						},
					},
					success: true,
				},
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 4096),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
							},
						},
					},
					success: true,
				},
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 4096),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
							},
						},
					},
					success: true,
				},
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 1),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
							},
						},
					},
					success: false,
				},
			},
		},
		{
			name: "TestPerformTrafficMonitoringDifferentReservationsHaveNoImpact",
			entries: []entry{
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 16384),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
							},
						},
					},
					success: true,
				},
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 16384),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "B",
							ActiveIndexId: 0,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
							},
						},
					},
					success: true,
				},
			},
		},
		{
			name: "TestPerformTrafficMonitoringSeveralReservationIndicesMapToSameBucket",
			entries: []entry{
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 16384),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
							},
						},
					},
					success: true,
				},
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 1),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 1,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
								1: {
									Index:    1,
									Validity: startTime.Add(2),
									BwCls:    1,
								},
							},
						},
					},
					success: false,
				},
			},
		},
		{
			name: "TestPerformTrafficMonitoringIncreasedBandwidth",
			entries: []entry{
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 16384),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
							},
						},
					},
					success: true,
				},
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 22528),
						PktArrivalTime: startTime.Add(1 * time.Second),
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 1,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    1,
								},
								1: {
									Index:    1,
									Validity: startTime.Add(2 * time.Second),
									BwCls:    2,
								},
							},
						},
					},
					success: true,
				},
			},
		},
		{
			name: "TestPerformTrafficMonitoringDecreasedBandwidth",
			entries: []entry{
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 22528),
						PktArrivalTime: startTime,
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*reservation.ReservationIndex{
								0: {
									Index:    0,
									Validity: startTime.Add(1),
									BwCls:    2,
								},
							},
						},
					},
					success: true,
				},
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 16384),
						PktArrivalTime: startTime.Add(1 * time.Second),
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 1,
							Indices: map[uint8]*reservation.ReservationIndex{
								1: {
									Index:    1,
									Validity: startTime.Add(2 * time.Second),
									BwCls:    1,
								},
							},
						},
					},
					success: true,
				},
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 1),
						PktArrivalTime: startTime.Add(1 * time.Second),
						Reservation: &reservation.Reservation{
							ReservationId: "A",
							ActiveIndexId: 1,
							Indices: map[uint8]*reservation.ReservationIndex{
								1: {
									Index:    1,
									Validity: startTime.Add(2 * time.Second),
									BwCls:    1,
								},
							},
						},
					},
					success: false,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, en := range tc.entries {
				err := worker.PerformTrafficMonitoring(&en.proc)
				assert.True(t, (err == nil && en.success) || (err != nil && !en.success))
			}
			worker.ResetTokenBucket()
		})
	}
}
