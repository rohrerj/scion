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

package grpc

import (
	"context"

	"github.com/scionproto/scion/go/coligate/reservation"
	libaddr "github.com/scionproto/scion/go/lib/addr"
	libtypes "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
	common "github.com/scionproto/scion/go/pkg/coligate"
	cgpb "github.com/scionproto/scion/go/pkg/proto/coligate"
)

type Coligate struct {
	Salt                string
	ReservationChannels []chan *reservation.ReservationTask
	CleanupChannel      chan *reservation.ReservationTask
}

var _ cgpb.ColibriGatewayServer = (*Coligate)(nil)

func (s *Coligate) UpdateSigmas(ctx context.Context, msg *cgpb.UpdateSigmasRequest) (*cgpb.UpdateSigmasResponse, error) {
	id, err := libtypes.NewID(libaddr.AS(msg.Asid), msg.Suffix)
	if err != nil {
		return nil, err
	}
	resId := string(id.ToRaw())

	task := &reservation.ReservationTask{
		ResId: resId,
		Reservation: &reservation.Reservation{
			ReservationId: resId,
			Rlc:           uint8(msg.Rlc),
			Indices: map[uint8]*reservation.ReservationIndex{
				uint8(msg.Index): {
					Index:    uint8(msg.Index),
					Validity: util.SecsToTime(msg.ExpirationTime),
					BwCls:    uint8(msg.Bwcls),
					Macs:     msg.Macs,
				},
			},
			Hops: make([]reservation.HopField, len(msg.HopInterfaces)),
		},
		HighestValidity: util.SecsToTime(msg.ExpirationTime),
	}

	for i, hop := range msg.HopInterfaces {
		task.Reservation.Hops[i].EgressId = uint16(hop.Egressid)
		task.Reservation.Hops[i].IngressId = uint16(hop.Ingressid)
	}

	s.CleanupChannel <- task

	//we have to create a new hasher because of concurrency
	s.ReservationChannels[common.CreateFnv1aHasher(s.Salt).Hash(task.ResId)] <- task

	return nil, nil
}
