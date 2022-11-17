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
	"math"
	"time"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/coligate/reservation"
	Tokenbucket "github.com/scionproto/scion/go/coligate/tokenbucket"
	libcolibri "github.com/scionproto/scion/go/lib/colibri/dataplane"
	libtypes "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/pkg/coligate/config"
)

//TODO(rohrerj) Add Unit tests

type Worker struct {
	InitialCoreIdCounter    uint32
	CoreIdCounter           uint32
	NumCounterBits          int
	Storage                 *reservation.ReservationStorage
	ColigatePacketProcessor *coligatePacketProcessor
	TokenBuckets            map[string]*Tokenbucket.TokenBucket //every worker has its own map of tokenbuckets that it is responsible for
}

type coligatePacketProcessor struct {
	totalLength           uint32
	pktArrivalTime        time.Time
	scionLayer            *slayers.SCION
	colibriPath           *colibri.ColibriPath
	reservation           *reservation.Reservation
	tokenbucketIdentifier string
	rawPacket             []byte
}

// Parses the scion and colibri header from a raw packet
func Parse(rawPacket []byte) (*coligatePacketProcessor, error) {
	proc := coligatePacketProcessor{}
	proc.rawPacket = rawPacket
	proc.totalLength = uint32(len(rawPacket))
	proc.scionLayer = &slayers.SCION{}
	var err error
	if err := proc.scionLayer.DecodeFromBytes(rawPacket, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}
	var ok bool
	p, ok := proc.scionLayer.Path.(*colibri.ColibriPathMinimal)
	if !ok {
		return nil, serrors.New("getting colibri minmal path failed")
	}
	if proc.colibriPath, err = p.ToColibriPath(); err != nil {
		return nil, serrors.New("expanding colibri path failed")
	}
	return &proc, nil
}

// initializes the worker with his id, tokenbuckets and reservations
func (w *Worker) InitWorker(config *config.ColigateConfig, workerId uint32, gatewayId uint32) error {

	w.CoreIdCounter = (gatewayId << (32 - config.NumBitsForGatewayId)) | (workerId << (32 - config.NumBitsForGatewayId - config.NumBitsForWorkerId))
	w.InitialCoreIdCounter = w.CoreIdCounter
	w.NumCounterBits = config.NumBitsForPerWorkerCounter

	w.TokenBuckets = make(map[string]*Tokenbucket.TokenBucket)
	w.ColigatePacketProcessor = &coligatePacketProcessor{}

	w.Storage = &reservation.ReservationStorage{}
	w.Storage.InitStorage()
	return nil
}

// updates, creates or deletes a reservation depending on the reservation task
func (w *Worker) handleReservationTask(task *reservation.ReservationTask) error {
	if w == nil || w.Storage == nil || task == nil {
		return serrors.New("handleReservationTask requires a valid worker and task")
	}
	if task.IsDeleteQuery {
		w.Storage.Delete(task)
	} else {
		w.Storage.Update(task)
	}

	return nil
}

// processes the current packet based on the current coligatePacketProcessor
func (w *Worker) process() error {
	if w == nil {
		return serrors.New("worker must not be nil")
	}

	if w.ColigatePacketProcessor == nil {
		return serrors.New("coligate packet processor must not be nil")
	}
	var err error
	err = w.validate()
	if err != nil {
		return err
	}
	err = w.performTrafficMonitoring()
	if err != nil {
		return err
	}

	return w.updateFields()
}

// validates the fields in the colibri header and checks that a valid reservation exists
func (w *Worker) validate() error {
	C := w.ColigatePacketProcessor.colibriPath.InfoField.C
	R := w.ColigatePacketProcessor.colibriPath.InfoField.R
	S := w.ColigatePacketProcessor.colibriPath.InfoField.S
	resIDSuffix := w.ColigatePacketProcessor.colibriPath.InfoField.ResIdSuffix
	if C || R || S { //TODO(rohrerj) I assume reverse packets make no sense here?
		return serrors.New("Invalid flags", "S", S, "R", R, "C", C)
	}
	id, err := libtypes.NewID(w.ColigatePacketProcessor.scionLayer.SrcIA.AS(), resIDSuffix)
	if err != nil {
		return serrors.New("Cannot parse reservation id")
	}
	resID := string(id.ToRaw())

	reservation, isValid := w.Storage.UseReservation(string(resID), w.ColigatePacketProcessor.colibriPath.InfoField.Ver, w.ColigatePacketProcessor.pktArrivalTime)
	if !isValid {
		return serrors.New("E2E reservation is invalid")
	}
	if len(reservation.Current().Macs) != len(w.ColigatePacketProcessor.colibriPath.HopFields) {
		return serrors.New("Number of hopfields is invalid")
	}
	w.ColigatePacketProcessor.reservation = reservation
	w.ColigatePacketProcessor.tokenbucketIdentifier = resID
	return nil
}

// checks that the reservation is not overused
func (w *Worker) performTrafficMonitoring() error {
	bucket, exists := w.TokenBuckets[w.ColigatePacketProcessor.tokenbucketIdentifier]
	entry := Tokenbucket.TokenBucketEntry{Length: uint64(w.ColigatePacketProcessor.totalLength), ArrivalTime: w.ColigatePacketProcessor.pktArrivalTime}
	realBandwidth := uint64(8192 * math.Sqrt(math.Pow(2, float64(w.ColigatePacketProcessor.reservation.Current().BwCls-1))))

	if !exists {
		bucket = &Tokenbucket.TokenBucket{}
		bucket.CurrentTokens = float64(realBandwidth)
		bucket.TokenIntervalInMs = 1 //TODO(rohrerj) use real value
		w.TokenBuckets[w.ColigatePacketProcessor.tokenbucketIdentifier] = bucket
	}

	bucket.CIRInBytes = realBandwidth
	ok := bucket.ValidateBandwidth(&entry)
	if !ok {
		return serrors.New("data packet exceeded bandwidth")
	}

	return nil
}

// update the colibri header fields
func (w *Worker) updateFields() error {

	currentVersion := w.ColigatePacketProcessor.reservation.Current()
	var expTick uint32 = uint32(currentVersion.Validity.Unix() / 4)
	tsRel, err := libcolibri.CreateTsRel(expTick, w.ColigatePacketProcessor.pktArrivalTime)
	if err != nil {
		return err
	}
	w.CoreIdCounter = w.InitialCoreIdCounter | (w.CoreIdCounter+1)%(1<<w.NumCounterBits)

	w.ColigatePacketProcessor.colibriPath.PacketTimestamp = libcolibri.CreateColibriTimestampCustom(tsRel, w.CoreIdCounter)

	//Update InfoField
	w.ColigatePacketProcessor.colibriPath.InfoField.BwCls = currentVersion.BwCls
	w.ColigatePacketProcessor.colibriPath.InfoField.Rlc = w.ColigatePacketProcessor.reservation.Rlc
	w.ColigatePacketProcessor.colibriPath.InfoField.HFCount = uint8(len(currentVersion.Macs))
	w.ColigatePacketProcessor.colibriPath.InfoField.Ver = uint8(currentVersion.Index)
	w.ColigatePacketProcessor.colibriPath.InfoField.CurrHF = 0
	w.ColigatePacketProcessor.colibriPath.InfoField.ExpTick = uint32(expTick)

	//Update Hopfields and MACS //TODO(rohrerj) add hop updates and mac computation
	/*for i, _ := range currentVersion.Macs {
		sizeBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(sizeBytes, w.ColigatePacketProcessor.totalLength)

		hash, err := scrypto.InitMac(mac)
		if err != nil {
			return err
		}
		_, err = hash.Write(w.ColigatePacketProcessor.colibriPath.PacketTimestamp[:])
		if err != nil {
			return err
		}
		_, err = hash.Write(sizeBytes)
		if err != nil {
			return err
		}
		w.ColigatePacketProcessor.colibriPath.HopFields[i].Mac = hash.Sum(nil)[:4]
		w.ColigatePacketProcessor.colibriPath.HopFields[i].IngressId = w.ColigatePacketProcessor.reservation.Hops[i].IngressId
		w.ColigatePacketProcessor.colibriPath.HopFields[i].EgressId = w.ColigatePacketProcessor.reservation.Hops[i].EgressId
	}*/
	return nil
}
