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

	"github.com/scionproto/scion/go/coligate/storage"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	common "github.com/scionproto/scion/go/pkg/coligate"
)

func (p *Processor) InitCleanupRoutine() {
	p.initCleanupRoutine()
}
func (p *Processor) SetHasher(salt []byte) {
	p.saltHasher = common.NewFnv1aHasher(salt)
}

func (p *Processor) SetNumWorkers(numWorkers int) {
	p.numWorkers = numWorkers
}

func (p *Processor) CreateCleanupChannel(maxQueueSize int) chan *storage.UpdateTask {
	p.cleanupChannel = make(chan *storage.UpdateTask, maxQueueSize)
	return p.cleanupChannel
}

func (p *Processor) CreateDataChannels(numberWorkers int, maxQueueSizePerWorker int) []chan *dataPacket {
	p.dataChannels = make([]chan *dataPacket, numberWorkers)
	for i := 0; i < numberWorkers; i++ {
		p.dataChannels[i] = make(chan *dataPacket, maxQueueSizePerWorker)
	}
	return p.dataChannels
}

func (p *Processor) CreateControlUpdateChannels(numberWorkers int, maxQueueSizePerWorker int) []chan *storage.UpdateTask {
	p.controlUpdateChannels = make([]chan *storage.UpdateTask, numberWorkers)
	for i := 0; i < numberWorkers; i++ {
		p.controlUpdateChannels[i] = make(chan *storage.UpdateTask, maxQueueSizePerWorker)
	}
	return p.controlUpdateChannels
}

func (p *Processor) CreateControlDeletionChannels(numberWorkers int, maxQueueSizePerWorker int) []chan *storage.DeletionTask {
	p.controlDeletionChannels = make([]chan *storage.DeletionTask, numberWorkers)
	for i := 0; i < numberWorkers; i++ {
		p.controlDeletionChannels[i] = make(chan *storage.DeletionTask, maxQueueSizePerWorker)
	}
	return p.controlDeletionChannels
}

func InitializeMetrics() *ColigateMetrics {
	return initializeMetrics(common.NewMetrics())
}

func (p *Processor) SetMetrics(m *ColigateMetrics) {
	p.metrics = m
}

func (p *Processor) Shutdown() {
	p.shutdown()
}

type DataPacket struct {
	PktArrivalTime time.Time
	ScionLayer     *slayers.SCION
	ColibriPath    *colibri.ColibriPath
	Reservation    *storage.Reservation
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

func (w *Worker) Validate(proc *DataPacket) error {
	return w.validate(internalParse(proc))
}

func (w *Worker) PerformTrafficMonitoring(proc *DataPacket) error {
	return w.performTrafficMonitoring(internalParse(proc))
}

func (w *Worker) Stamp(d *DataPacket) error {
	return w.stamp(internalParse((d)))
}

func (w *Worker) UpdateCounter() {
	w.updateCounter()
}
