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
	libmetrics "github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/util"
	common "github.com/scionproto/scion/go/pkg/coligate"
	cgpb "github.com/scionproto/scion/go/pkg/proto/coligate"
)

type Coligate struct {
	Hasher                       common.SaltHasher
	ReservationChannels          []chan *reservation.ReservationTask
	CleanupChannel               chan *reservation.ReservationTask
	UpdateSigmasTotalPromCounter libmetrics.Counter
}

var _ cgpb.ColibriGatewayServer = (*Coligate)(nil)

func (s *Coligate) UpdateSigmas(ctx context.Context, msg *cgpb.UpdateSigmasRequest) (*cgpb.UpdateSigmasResponse, error) {
	id, err := libtypes.NewID(libaddr.AS(msg.Asid), msg.Suffix)
	if err != nil {
		return nil, err
	}
	resId := string(id.ToRaw())
	s.UpdateSigmasTotalPromCounter.Add(1)
	task := &reservation.ReservationTask{
		ResId: resId,
		Reservation: &reservation.Reservation{
			Id:  resId,
			Rlc: uint8(msg.Rlc),
			Indices: map[uint8]*reservation.ReservationIndex{
				uint8(msg.Index): {
					Index:    uint8(msg.Index),
					Validity: util.SecsToTime(msg.ExpirationTime),
					BwCls:    uint8(msg.Bwcls),
					Sigmas:   msg.Macs,
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

	s.ReservationChannels[s.Hasher.Hash(id.ToRaw())] <- task

	return nil, nil
}
