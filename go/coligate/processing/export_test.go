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
	"time"

	"github.com/scionproto/scion/go/coligate/reservation"
	Tokenbucket "github.com/scionproto/scion/go/coligate/tokenbucket"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	common "github.com/scionproto/scion/go/pkg/coligate"
)

func (control *Control) InitCleanupRoutine(metrics *common.Metrics) {
	control.initCleanupRoutine(metrics)
}
func (control *Control) SetHasher(salt []byte) {
	control.saltHasher = common.NewFnv1aHasher(salt)
}

func (control *Control) CreateCleanupChannel(maxQueueSize int) chan *reservation.ReservationTask {
	control.cleanupChannel = make(chan *reservation.ReservationTask, maxQueueSize)
	return control.cleanupChannel
}

func (control *Control) CreateDataChannels(numberWorkers int, maxQueueSizePerWorker int) []chan *dataPacket {
	control.dataChannels = make([]chan *dataPacket, numberWorkers)
	for i := 0; i < numberWorkers; i++ {
		control.dataChannels[i] = make(chan *dataPacket, maxQueueSizePerWorker)
	}
	return control.dataChannels
}

func (control *Control) CreateControlChannels(numberWorkers int, maxQueueSizePerWorker int) []chan *reservation.ReservationTask {
	control.controlChannels = make([]chan *reservation.ReservationTask, numberWorkers)
	for i := 0; i < numberWorkers; i++ {
		control.controlChannels[i] = make(chan *reservation.ReservationTask, maxQueueSizePerWorker)
	}
	return control.controlChannels
}

func (control *Control) Shutdown() {
	control.shutdown()
}

type DataPacket struct {
	PktArrivalTime time.Time
	ScionLayer     *slayers.SCION
	ColibriPath    *colibri.ColibriPath
	Reservation    *reservation.Reservation
	RawPacket      []byte
}

func internalParse(proc *DataPacket) *dataPacket {
	return &dataPacket{
		pktArrivalTime: proc.PktArrivalTime,
		scionLayer:     proc.ScionLayer,
		colibriPath:    proc.ColibriPath,
		reservation:    proc.Reservation,
		rawPacket:      proc.RawPacket,
	}
}

func (w *Worker) HandleReservationTask(task *reservation.ReservationTask) error {
	return w.handleReservationTask(task)
}

func (w *Worker) Validate(proc *DataPacket) error {
	return w.validate(internalParse(proc))
}

func (w *Worker) PerformTrafficMonitoring(proc *DataPacket) error {
	return w.performTrafficMonitoring(internalParse(proc))
}

func (w *Worker) ResetTokenBucket() {
	w.TokenBuckets = make(map[string]*Tokenbucket.TokenBucket)
}
