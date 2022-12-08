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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/coligate/processing"
	"github.com/scionproto/scion/go/coligate/storage"
	"github.com/scionproto/scion/go/lib/addr"
	libcolibri "github.com/scionproto/scion/go/lib/colibri/dataplane"
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

func TestValidate(t *testing.T) {
	type entry struct {
		proc processing.DataPacket
		err  string
	}

	type test struct {
		name     string
		entries  []entry
		resStore map[string]*storage.Reservation
	}
	worker := processing.NewWorker(getColigateConfiguration(), 1, 1, 1)

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
					err: "Invalid flags",
				},
			},
		},
		{
			name: "TestValidateRFlagIsSet",
			entries: []entry{
				{
					proc: processing.DataPacket{
						PktArrivalTime: startTime,
						ColibriPath: &colibri.ColibriPath{
							InfoField: &colibri.InfoField{
								R: true,
							},
						},
					},
					err: "Invalid flags",
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
					err: "Invalid flags",
				},
			},
		},
		{
			name: "TestValidateReservationBelongsToOtherAS",
			resStore: map[string]*storage.Reservation{
				string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}): {
					Id: string(
						[]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
					Hops:          make([]storage.HopField, 1),
					ActiveIndexId: 0,
					Indices: map[uint8]*storage.ReservationIndex{
						0: {
							Index:    0,
							Validity: startTime.Add(1),
							BwCls:    1,
							Sigmas:   make([][]byte, 1),
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
							SrcIA: addr.MustIAFrom(1, 2),
						},
					},
					err: "Reservation does not belong to local AS",
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
					err: "E2E reservation is invalid",
				},
			},
		},
		{
			name: "TestValidateInvalidNumberOfHopfields",
			resStore: map[string]*storage.Reservation{
				string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}): {
					Id: string(
						[]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
					Hops:          make([]storage.HopField, 1),
					ActiveIndexId: 0,
					Indices: map[uint8]*storage.ReservationIndex{
						0: {
							Index:    0,
							Validity: startTime.Add(1),
							BwCls:    1,
							Sigmas:   make([][]byte, 1),
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
					err: "Number of hopfields is invalid",
				},
			},
		},
		{
			name: "TestValidateCurrHFIsInvalid",
			resStore: map[string]*storage.Reservation{
				string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}): {
					Id: string(
						[]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
					Hops:          make([]storage.HopField, 1),
					ActiveIndexId: 0,
					Indices: map[uint8]*storage.ReservationIndex{
						0: {
							Index:    0,
							Validity: startTime.Add(1),
							BwCls:    1,
							Sigmas:   make([][]byte, 1),
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
								CurrHF:      1,
							},
							HopFields: make([]*colibri.HopField, 1),
						},
						ScionLayer: &slayers.SCION{
							SrcIA: addr.MustIAFrom(1, 1),
						},
					},
					err: "CurrHF is invalid",
				},
			},
		},
		{
			name: "TestValidateBwClsIsInvalid",
			resStore: map[string]*storage.Reservation{
				string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}): {
					Id: string(
						[]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
					Hops:          make([]storage.HopField, 1),
					ActiveIndexId: 0,
					Indices: map[uint8]*storage.ReservationIndex{
						0: {
							Index:    0,
							Validity: startTime.Add(1),
							BwCls:    1,
							Sigmas:   make([][]byte, 1),
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
								CurrHF:      0,
								BwCls:       2,
							},
							HopFields: make([]*colibri.HopField, 1),
						},
						ScionLayer: &slayers.SCION{
							SrcIA: addr.MustIAFrom(1, 1),
						},
					},
					err: "Bandwidth class is invalid",
				},
			},
		},
		{
			name: "TestValidateRlcIsInvalid",
			resStore: map[string]*storage.Reservation{
				string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}): {
					Id: string(
						[]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
					Hops:          make([]storage.HopField, 1),
					ActiveIndexId: 0,
					Indices: map[uint8]*storage.ReservationIndex{
						0: {
							Index:    0,
							Validity: startTime.Add(1),
							BwCls:    1,
							Sigmas:   make([][]byte, 1),
						},
					},
					Rlc: 1,
				},
			},
			entries: []entry{
				{
					proc: processing.DataPacket{
						PktArrivalTime: startTime,
						ColibriPath: &colibri.ColibriPath{
							InfoField: &colibri.InfoField{
								ResIdSuffix: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
								CurrHF:      0,
								BwCls:       1,
								Rlc:         2,
							},
							HopFields: make([]*colibri.HopField, 1),
						},
						ScionLayer: &slayers.SCION{
							SrcIA: addr.MustIAFrom(1, 1),
						},
					},
					err: "Latency class is invalid",
				},
			},
		},
		{
			name: "TestValidateExpTickIsInvalid",
			resStore: map[string]*storage.Reservation{
				string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}): {
					Id: string(
						[]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
					Hops:          make([]storage.HopField, 1),
					ActiveIndexId: 0,
					Indices: map[uint8]*storage.ReservationIndex{
						0: {
							Index:    0,
							Validity: startTime.Add(100 * time.Second),
							BwCls:    1,
							Sigmas:   make([][]byte, 1),
						},
					},
					Rlc: 1,
				},
			},
			entries: []entry{
				{
					proc: processing.DataPacket{
						PktArrivalTime: startTime,
						ColibriPath: &colibri.ColibriPath{
							InfoField: &colibri.InfoField{
								ResIdSuffix: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
								CurrHF:      0,
								BwCls:       1,
								Rlc:         1,
								ExpTick:     1,
							},
							HopFields: make([]*colibri.HopField, 1),
						},
						ScionLayer: &slayers.SCION{
							SrcIA: addr.MustIAFrom(1, 1),
						},
					},
					err: "ExpTick is invalid",
				},
			},
		},
		{
			name: "TestValidateInvalidIngressId",
			resStore: map[string]*storage.Reservation{
				string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}): {
					Id: string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
					Hops: []storage.HopField{
						{
							IngressId: 1,
							EgressId:  2,
						},
					},
					ActiveIndexId: 0,
					Rlc:           1,
					Indices: map[uint8]*storage.ReservationIndex{
						0: {
							Index:    0,
							Validity: startTime.Add(100 * time.Second),
							BwCls:    1,
							Sigmas:   make([][]byte, 1),
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
								Ver:         0,
								BwCls:       1,
								Rlc:         1,
								HFCount:     1,
								ExpTick:     uint32(startTime.Add(100*time.Second).Unix() / 4),
							},
							HopFields: []*colibri.HopField{
								{
									IngressId: 3,
									EgressId:  2,
								},
							},
						},
						ScionLayer: &slayers.SCION{
							SrcIA: addr.MustIAFrom(1, 1),
						},
					},
					err: "IngressId is invalid",
				},
			},
		},
		{
			name: "TestValidateInvalidEgressId",
			resStore: map[string]*storage.Reservation{
				string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}): {
					Id: string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
					Hops: []storage.HopField{
						{
							IngressId: 1,
							EgressId:  2,
						},
					},
					ActiveIndexId: 0,
					Rlc:           1,
					Indices: map[uint8]*storage.ReservationIndex{
						0: {
							Index:    0,
							Validity: startTime.Add(100 * time.Second),
							BwCls:    1,
							Sigmas:   make([][]byte, 1),
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
								Ver:         0,
								BwCls:       1,
								Rlc:         1,
								HFCount:     1,
								ExpTick:     uint32(startTime.Add(100*time.Second).Unix() / 4),
							},
							HopFields: []*colibri.HopField{
								{
									IngressId: 1,
									EgressId:  3,
								},
							},
						},
						ScionLayer: &slayers.SCION{
							SrcIA: addr.MustIAFrom(1, 1),
						},
					},
					err: "EgressId is invalid",
				},
			},
		},
		{
			name: "TestValidateAllValid",
			resStore: map[string]*storage.Reservation{
				string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}): {
					Id: string([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
					Hops: []storage.HopField{
						{
							IngressId: 1,
							EgressId:  2,
						},
					},
					ActiveIndexId: 0,
					Rlc:           1,
					Indices: map[uint8]*storage.ReservationIndex{
						0: {
							Index:    0,
							Validity: startTime.Add(100 * time.Second),
							BwCls:    1,
							Sigmas:   make([][]byte, 1),
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
								Ver:         0,
								BwCls:       1,
								Rlc:         1,
								HFCount:     1,
								ExpTick:     uint32(startTime.Add(100*time.Second).Unix() / 4),
							},
							HopFields: []*colibri.HopField{
								{
									IngressId: 1,
									EgressId:  2,
								},
							},
						},
						ScionLayer: &slayers.SCION{
							SrcIA: addr.MustIAFrom(1, 1),
						},
					},
					err: "",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			worker.Storage.InitStorageWithData(tc.resStore)
			for _, en := range tc.entries {
				err := worker.Validate(&en.proc)
				if en.err == "" {
					assert.NoError(t, err)
				} else {
					assert.True(t, strings.HasPrefix(err.Error(), en.err), err.Error())
				}
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
	worker := processing.NewWorker(getColigateConfiguration(), 1, 1, 1)

	var startTime = time.Unix(0, 0)

	tests := []test{
		{
			name: "TestPerformTrafficMonitoringOnePacketFullBandwidth",
			entries: []entry{
				{
					proc: processing.DataPacket{
						RawPacket:      make([]byte, 16384),
						PktArrivalTime: startTime,
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "B",
							ActiveIndexId: 0,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 1,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 1,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 0,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 1,
							Indices: map[uint8]*storage.ReservationIndex{
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
						Reservation: &storage.Reservation{
							Id:            "A",
							ActiveIndexId: 1,
							Indices: map[uint8]*storage.ReservationIndex{
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
			m := make(map[string]*storage.TrafficMonitor)
			for _, en := range tc.entries {
				monitor := m[en.proc.Reservation.Id]
				en.proc.Reservation.TrafficMonitor = monitor
				err := worker.PerformTrafficMonitoring(&en.proc)
				m[en.proc.Reservation.Id] = en.proc.Reservation.TrafficMonitor
				assert.True(t, (err == nil && en.success) || (err != nil && !en.success))
			}
		})
	}
}

func TestUpdateCounter(t *testing.T) {
	w := processing.NewWorker(&config.ColigateConfig{
		NumBitsForGatewayId:        8,
		NumBitsForWorkerId:         8,
		NumBitsForPerWorkerCounter: 16,
	}, 13, 3, 1)
	// Check that it starts with the correct value
	assert.Equal(t, uint32(0x30d0000), w.CoreIdCounter)

	// Check that increments in the first few bits works
	for i := 1; i <= 16; i++ {
		w.UpdateCounter()
		assert.Equal(t, uint32(0x30d0000+i), w.CoreIdCounter)
	}

	// Check that increments in the last few bits works
	w.CoreIdCounter = 0x30dfff0
	for i := 0xfff1; i <= 0xffff; i++ {
		w.UpdateCounter()
		assert.Equal(t, uint32(0x30d0000+i), w.CoreIdCounter)
	}
	// Check that the wraparound works
	w.UpdateCounter()
	assert.Equal(t, uint32(0x30d0000), w.CoreIdCounter)
}

// TestUpdateMacs tests that for a valid sigma, UpdateFields computes the correct mac values that
// can be verified with the help of the private key.
func TestUpdateMacs(t *testing.T) {
	privateKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	privateKeyCipher, err := libcolibri.InitColibriKey(privateKey)
	assert.NoError(t, err)

	w := processing.NewWorker(getColigateConfiguration(), 1, 1, 1)

	d := &processing.DataPacket{
		PktArrivalTime: time.Unix(0, 0),
		RawPacket:      make([]byte, 200),
		ColibriPath: &colibri.ColibriPath{
			InfoField: &colibri.InfoField{
				ExpTick:     1,
				OrigPayLen:  0,
				HFCount:     1,
				ResIdSuffix: make([]byte, 12),
			},
			HopFields: []*colibri.HopField{
				{
					IngressId: 1,
					EgressId:  2,
					Mac:       make([]byte, 4),
				},
			},
		},
		ScionLayer: &slayers.SCION{
			SrcAddrType: slayers.T4Ip,
			DstAddrType: slayers.T4Ip,
			SrcAddrLen:  slayers.AddrLen4,
			DstAddrLen:  slayers.AddrLen4,
			RawSrcAddr:  []byte("1234"),
			RawDstAddr:  []byte("5678"),
			SrcIA:       addr.MustIAFrom(1, 1),
			DstIA:       addr.MustIAFrom(2, 2),
			PathType:    colibri.PathType,
		},
		Reservation: &storage.Reservation{
			Id:            "A",
			ActiveIndexId: 0,
			Hops: []storage.HopField{
				{
					IngressId: 1,
					EgressId:  2,
				},
			},
			Indices: map[uint8]*storage.ReservationIndex{
				0: {
					Index:  0,
					Sigmas: make([][]byte, 1),
				},
			},
		},
	}
	// Create the sigma that colibri service would later send to colibri gateway
	sigmaBuffer := make([]byte, 16)
	err = libcolibri.MACSigma(sigmaBuffer, privateKeyCipher, d.ColibriPath.InfoField,
		d.ColibriPath.HopFields[0], d.ScionLayer)
	assert.NoError(t, err)

	// Update mac fields of EE data packet with wrong sigma
	d.Reservation.Indices[0].Sigmas[0] = []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	err = w.Stamp(d)
	assert.NoError(t, err)
	// Validate the computed mac
	err = libcolibri.VerifyMAC(privateKeyCipher, d.ColibriPath.PacketTimestamp,
		d.ColibriPath.InfoField, d.ColibriPath.HopFields[0], d.ScionLayer)
	assert.Error(t, err)

	// Update mac fields of EE data packet with correct sigma
	d.Reservation.Indices[0].Sigmas[0] = sigmaBuffer
	err = w.Stamp(d)
	assert.NoError(t, err)
	// Validate the computed mac
	err = libcolibri.VerifyMAC(privateKeyCipher, d.ColibriPath.PacketTimestamp,
		d.ColibriPath.InfoField, d.ColibriPath.HopFields[0], d.ScionLayer)
	assert.NoError(t, err)
}
