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

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/coligate/storage"
	"github.com/scionproto/scion/go/coligate/tokenbucket"
	libaddr "github.com/scionproto/scion/go/lib/addr"
	libcolibri "github.com/scionproto/scion/go/lib/colibri/dataplane"
	libtypes "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/pkg/coligate/config"
)

type Worker struct {
	InitialCoreIdCounter uint32
	CoreIdCounter        uint32
	NumCounterBits       int
	Storage              *storage.Storage
	LocalAS              libaddr.AS
}

type dataPacket struct {
	pktArrivalTime time.Time
	scionLayer     *slayers.SCION
	colibriPath    *colibri.ColibriPath
	reservation    *storage.Reservation
	rawPacket      []byte
}

// Parse parses the scion and colibri header from a raw packet
// TODO(rohrerj) This parses the path twice, optimize
func Parse(rawPacket []byte) (*dataPacket, error) {
	proc := dataPacket{
		rawPacket:  rawPacket,
		scionLayer: &slayers.SCION{},
	}
	var err error
	if err := proc.scionLayer.DecodeFromBytes(rawPacket, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}
	var ok bool
	p, ok := proc.scionLayer.Path.(*colibri.ColibriPathMinimal)
	if !ok {
		return nil, serrors.New("getting colibri minimal path failed")
	}
	if proc.colibriPath, err = p.ToColibriPath(); err != nil {
		return nil, serrors.New("expanding colibri path failed")
	}
	return &proc, nil
}

// NewWorker initializes the worker with its id, tokenbuckets and reservations
func NewWorker(config *config.ColigateConfig, workerId uint32, gatewayId uint32, localAS libaddr.AS) *Worker {
	w := &Worker{
		CoreIdCounter:  (gatewayId << (32 - config.NumBitsForGatewayId)) | (workerId << (32 - config.NumBitsForGatewayId - config.NumBitsForWorkerId)),
		NumCounterBits: config.NumBitsForPerWorkerCounter,
		LocalAS:        localAS,
		Storage:        &storage.Storage{},
	}
	w.InitialCoreIdCounter = w.CoreIdCounter
	w.Storage.InitStorageWithData(nil)
	return w
}

// Processes the current packet based on the current dataPacket
func (w *Worker) process(d *dataPacket) error {
	if w == nil {
		return serrors.New("worker must not be nil")
	}

	if d == nil {
		return serrors.New("datapacket must not be nil")
	}
	var err error
	err = w.validate(d)
	if err != nil {
		return err
	}
	err = w.performTrafficMonitoring(d)
	if err != nil {
		return err
	}

	return w.stamp(d)
}

// Validates the fields in the colibri header and checks that a valid reservation exists
func (w *Worker) validate(d *dataPacket) error {
	infoField := d.colibriPath.InfoField
	C := infoField.C
	R := infoField.R
	S := infoField.S
	resIDSuffix := infoField.ResIdSuffix
	if C || R || S {
		return serrors.New("Invalid flags", "S", S, "R", R, "C", C)
	}
	id, err := libtypes.NewID((d).scionLayer.SrcIA.AS(), resIDSuffix) // TODO(rohrerj) change mapping of reservation id
	if err != nil {
		return serrors.New("Cannot parse reservation id")
	}
	if id.ASID != w.LocalAS {
		return serrors.New("Reservation does not belong to local AS")
	}
	resID := string(id.ToRaw())

	reservation, isValid := w.Storage.UseReservation(resID, infoField.Ver, d.pktArrivalTime)
	if !isValid {
		return serrors.New("E2E reservation is invalid")
	}
	d.reservation = reservation
	currentIndex := d.reservation.Current()

	if len(d.colibriPath.HopFields) != len(currentIndex.Sigmas) {
		return serrors.New("Number of hopfields is invalid", "expected", len(currentIndex.Sigmas), "actual", len(d.colibriPath.HopFields))
	}
	if infoField.CurrHF != 0 {
		return serrors.New("CurrHF is invalid", "expected", 0, "actual", infoField.CurrHF)
	}
	if infoField.BwCls != currentIndex.BwCls {
		return serrors.New("Bandwidth class is invalid", "expected", currentIndex.BwCls, "actual", infoField.BwCls)
	}
	if infoField.Rlc != d.reservation.Rlc {
		return serrors.New("Latency class is invalid", "expected", d.reservation.Rlc, "actual", infoField.Rlc)
	}
	if infoField.ExpTick != uint32(currentIndex.Validity.Unix()/4) {
		return serrors.New("ExpTick is invalid", "expected", currentIndex.Validity.Unix()/4, "actual", infoField.ExpTick)
	}
	for i, hop := range d.reservation.Hops {
		if d.colibriPath.HopFields[i].EgressId != hop.EgressId {
			return serrors.New("EgressId is invalid", "expected", hop.EgressId, "actual", d.colibriPath.HopFields[i].EgressId)
		}
		if d.colibriPath.HopFields[i].IngressId != hop.IngressId {
			return serrors.New("IngressId is invalid", "expected", hop.IngressId, "actual", d.colibriPath.HopFields[i].IngressId)
		}
	}
	return nil
}

// Checks that the reservation is not overused
func (w *Worker) performTrafficMonitoring(d *dataPacket) error {
	monitor := d.reservation.TrafficMonitor
	currentBwCls := d.reservation.Current().BwCls
	if monitor != nil {
		if monitor.LastBwcls != currentBwCls {
			realBandwidth := 1024 * libtypes.BWCls(currentBwCls).ToKbps()
			monitor.Bucket.SetRate(float64(realBandwidth))
			monitor.Bucket.SetBurstSize(float64(realBandwidth))
			monitor.LastBwcls = currentBwCls
		}
	} else {
		realBandwidth := 1024 * libtypes.BWCls(currentBwCls).ToKbps()
		// TODO(rohrerj) set correct value for burst size
		monitor = &storage.TrafficMonitor{
			Bucket:    tokenbucket.NewTokenBucket(d.pktArrivalTime, float64(realBandwidth), float64(realBandwidth)),
			LastBwcls: currentBwCls,
		}
		d.reservation.TrafficMonitor = monitor
	}

	if !monitor.Bucket.Apply(len(d.rawPacket), d.pktArrivalTime) {
		return serrors.New("data packet exceeded bandwidth")
	}
	return nil
}

func (w *Worker) updateCounter() {
	w.CoreIdCounter = w.InitialCoreIdCounter | (w.CoreIdCounter+1)%(1<<w.NumCounterBits)
}

// Updates the timestamp and HFVs
func (w *Worker) stamp(d *dataPacket) error {
	currentIndex := d.reservation.Current()
	tsRel, err := libcolibri.CreateTsRel(d.colibriPath.InfoField.ExpTick, d.pktArrivalTime)
	if err != nil {
		return err
	}
	w.updateCounter()

	d.colibriPath.PacketTimestamp = libcolibri.CreateColibriTimestampCustom(tsRel, w.CoreIdCounter)
	// Set HVF values
	for i, sigma := range currentIndex.Sigmas {
		cipher, err := libcolibri.InitColibriKey(sigma)
		if err != nil {
			return err
		}
		if err = libcolibri.MACE2EFromSigma(d.colibriPath.HopFields[i].Mac, cipher, d.colibriPath.InfoField, d.colibriPath.PacketTimestamp, d.scionLayer); err != nil {
			return err
		}
	}
	return d.colibriPath.SerializeTo(d.rawPacket[slayers.CmnHdrLen+d.scionLayer.AddrHdrLen():])
}
