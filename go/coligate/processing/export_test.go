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

package processing

import (
	"github.com/scionproto/scion/go/coligate/reservation"
	common "github.com/scionproto/scion/go/pkg/coligate"
)

func (control *Control) InitCleanupRoutine() {
	control.initCleanupRoutine()
}
func (control *Control) SetHasher(salt []byte) {
	control.saltHasher = common.NewFnv1aHasher(salt)
}

func (control *Control) CreateCleanupChannel(maxQueueSize int) chan *reservation.ReservationTask {
	control.cleanupChannel = make(chan *reservation.ReservationTask, maxQueueSize)
	return control.cleanupChannel
}

func (control *Control) CreateDataChannels(numberWorkers int, maxQueueSizePerWorker int) []chan *coligatePacketProcessor {
	control.dataChannels = make([]chan *coligatePacketProcessor, numberWorkers)
	for i := 0; i < numberWorkers; i++ {
		control.dataChannels[i] = make(chan *coligatePacketProcessor, maxQueueSizePerWorker)
	}
	return control.dataChannels
}

func (control *Control) CreateReservationChannels(numberWorkers int, maxQueueSizePerWorker int) []chan *reservation.ReservationTask {
	control.reservationChannels = make([]chan *reservation.ReservationTask, numberWorkers)
	for i := 0; i < numberWorkers; i++ {
		control.reservationChannels[i] = make(chan *reservation.ReservationTask, maxQueueSizePerWorker)
	}
	return control.reservationChannels
}

func (control *Control) Exit() {
	control.exit = true
	//close(control.cleanupChannel)
}
