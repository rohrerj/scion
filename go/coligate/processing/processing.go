package processing

import (
	"encoding/binary"
	"math"
	"time"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/go/coligate/reservation"
	Tokenbucket "github.com/scionproto/scion/go/coligate/tokenbucket"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/pkg/coligate/config"
)

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
	err := proc.scionLayer.DecodeFromBytes(rawPacket, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, err
	}
	var ok bool
	proc.colibriPath, ok = proc.scionLayer.Path.(*colibri.ColibriPath)
	if !ok {
		return nil, serrors.New("getting colibri path information failed")
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
	w.ColigatePacketProcessor.pktArrivalTime = time.Now()
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
	resID := w.ColigatePacketProcessor.colibriPath.InfoField.ResIdSuffix
	if C || R || S { //TODO I assume reverse packets make no sense here?
		return serrors.New("Invalid flags", "S", S, "R", R, "C", C)
	}
	reservation, isValid := w.Storage.IsReservationValid(string(resID), w.ColigatePacketProcessor.pktArrivalTime)
	if !isValid {
		return serrors.New("E2E reservation is invalid")
	}
	if len(reservation.Macs) != len(w.ColigatePacketProcessor.colibriPath.HopFields) {
		return serrors.New("Number of hopfields is invalid")
	}
	w.ColigatePacketProcessor.reservation = reservation
	w.ColigatePacketProcessor.tokenbucketIdentifier = string(resID)
	return nil
}

// checks that the reservation is not overused
func (w *Worker) performTrafficMonitoring() error {
	bucket, exists := w.TokenBuckets[w.ColigatePacketProcessor.tokenbucketIdentifier]
	entry := Tokenbucket.TokenBucketEntry{Length: uint64(w.ColigatePacketProcessor.totalLength), ArrivalTime: w.ColigatePacketProcessor.pktArrivalTime}
	realBandwidth := uint64(8192 * math.Sqrt(math.Pow(2, float64(w.ColigatePacketProcessor.reservation.BwCls-1))))

	if !exists {
		bucket = &Tokenbucket.TokenBucket{}
		bucket.CurrentTokens = float64(realBandwidth)
		bucket.TokenIntervalInMs = 1 //TODO use real value
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
	var expTick int64 = w.ColigatePacketProcessor.reservation.Validity.Unix() / 4
	var timestampNs int64 = (4*expTick - 16) * int64(math.Pow(10, 9))
	var tsRel uint32 = uint32((w.ColigatePacketProcessor.reservation.Validity.Unix() - timestampNs) / int64(4*time.Nanosecond))

	//Update Colibri Timestamp Field
	w.ColigatePacketProcessor.colibriPath.PacketTimestamp = colibri.Timestamp{}
	binary.BigEndian.PutUint32(w.ColigatePacketProcessor.colibriPath.PacketTimestamp[:3], tsRel)
	w.CoreIdCounter = w.InitialCoreIdCounter | (w.CoreIdCounter+1)%(1<<w.NumCounterBits)
	binary.BigEndian.PutUint32(w.ColigatePacketProcessor.colibriPath.PacketTimestamp[4:], w.CoreIdCounter)

	//Update InfoField
	w.ColigatePacketProcessor.colibriPath.InfoField.BwCls = w.ColigatePacketProcessor.reservation.BwCls
	w.ColigatePacketProcessor.colibriPath.InfoField.Rlc = w.ColigatePacketProcessor.reservation.Rlc
	w.ColigatePacketProcessor.colibriPath.InfoField.HFCount = uint8(len(w.ColigatePacketProcessor.reservation.Macs))
	w.ColigatePacketProcessor.colibriPath.InfoField.Ver = uint8(w.ColigatePacketProcessor.reservation.Version)
	w.ColigatePacketProcessor.colibriPath.InfoField.CurrHF = 0
	w.ColigatePacketProcessor.colibriPath.InfoField.ExpTick = uint32(expTick)

	//Update Hopfields and MACS
	for i, mac := range w.ColigatePacketProcessor.reservation.Macs {
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
		w.ColigatePacketProcessor.colibriPath.HopFields[i].Mac = hash.Sum(nil)[:3]
		w.ColigatePacketProcessor.colibriPath.HopFields[i].IngressId = w.ColigatePacketProcessor.reservation.Hops[i].IngressId
		w.ColigatePacketProcessor.colibriPath.HopFields[i].EgressId = w.ColigatePacketProcessor.reservation.Hops[i].EgressId
	}
	return nil
}
