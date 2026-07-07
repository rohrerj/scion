// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package marketplace

import (
	"context"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

func OneShotReservation(
	ctx context.Context,
	sdConn daemon.Connector,
	topo snet.Topology,
	marketplaceUrl string,
	token string,
	bwInKbps uint32,
	startsAt time.Time,
	stopsAt time.Time,
	maxPrice uint64,
	p snet.Path,
) (*snetpath.Reservation, error) {
	marketplaceClient, err := NewMarketplaceClient(ctx, marketplaceUrl, token, daemon.Querier{Connector: sdConn}, topo, true)
	if err != nil {
		return nil, serrors.Wrap("new marketplace client", err)
	}
	// Obtain the flyovers.
	flyovers, err := marketplaceClient.ObtainReservationsFullPath(ctx, p, bwInKbps, startsAt, stopsAt, maxPrice, ContinueOnError, true, true, 5)
	if err != nil {
		return nil, serrors.Wrap("redeeming flyovers", err)
	}
	for _, flyOver := range flyovers {
		fmt.Println("flyover", flyOver.IA, flyOver.Flyover)
	}
	// Build a reservation with the flyovers.
	return snetpath.NewReservation(
		snetpath.WithScionPath(p, snetpath.FlyoversToMap(flyovers)),
	)
}
