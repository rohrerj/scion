package grpc

import (
	"context"
	"hash/fnv"
	"strconv"

	"github.com/scionproto/scion/go/coligate/reservation"
	"github.com/scionproto/scion/go/lib/util"
	cgpb "github.com/scionproto/scion/go/pkg/proto/coligate"
)

type Coligate struct {
	Salt                string
	ReservationChannels []chan *reservation.ReservationTask
	CleanupChannel      chan *reservation.ReservationTask
}

var _ cgpb.ColibriGatewayServer = (*Coligate)(nil)

func (s *Coligate) UpdateSigmas(ctx context.Context, msg *cgpb.UpdateSigmasRequest) (*cgpb.UpdateSigmasResponse, error) {
	task := &reservation.ReservationTask{}
	task.ResId = strconv.FormatInt(int64(msg.GetAsid()), 10) + string(msg.GetSuffix())
	task.Reservation = &reservation.Reservation{}
	task.Reservation.ReservationId = task.ResId
	task.Reservation.Rlc = uint8(msg.Rlc)

	task.HighestValidity = util.SecsToTime(msg.ExpirationTime)

	task.Reservation.Indices = make(map[uint8]*reservation.ReservationIndex)
	task.Reservation.Indices[uint8(msg.Index)] = &reservation.ReservationIndex{
		Index:    uint8(msg.Index),
		Validity: task.HighestValidity,
		BwCls:    uint8(msg.Bwcls),
		Macs:     msg.Macs,
	}

	task.Reservation.Hops = make([]reservation.HopField, len(msg.HopInterfaces))
	for i, hop := range msg.HopInterfaces {
		task.Reservation.Hops[i].EgressId = uint16(hop.Egressid)
		task.Reservation.Hops[i].IngressId = uint16(hop.Ingressid)
	}

	s.CleanupChannel <- task
	s.ReservationChannels[hash(task.ResId, s.Salt)] <- task

	return nil, nil
}

// Internal method to calculate the hash value of a input string with a
// salt value. It uses the fnv-1a algorithm.
func hash(s string, salt string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s + salt))
	return h.Sum32()
}
