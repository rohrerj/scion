package grpc

import (
	"context"
	"hash/fnv"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/coligate/reservation"
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
	task.Reservation = &reservation.Reservation{}
	task.Reservation.ReservationId = strconv.FormatInt(int64(msg.GetAsid()), 10) + string(msg.GetSuffix())
	task.Reservation.Validity = time.Unix(msg.ValidityTimestamp, 0)
	task.Reservation.BwCls = uint8(msg.Bwcls)
	task.Reservation.Rlc = uint8(msg.Rlc)
	task.Reservation.Macs = msg.Macs
	task.ResId = task.Reservation.ReservationId

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
