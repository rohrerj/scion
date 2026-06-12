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
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
)

func (s *Service) newRedemptionServerPeer(ia addr.IA) *RedemptionServerPeer {
	peer := &RedemptionServerPeer{
		ia:      ia,
		sendCh:  make(chan *hummingbird.RedeemAssetFromASRequest, 64),
		pending: make(map[uint64]chan *hummingbird.RedeemAssetFromASResponse),
	}
	s.redemptionServerPeers[ia] = peer
	return peer
}

type RedemptionServerPeer struct {
	delegatedServer      *RedemptionService
	delegationExpiration time.Time
	ia                   addr.IA
	sendCh               chan *hummingbird.RedeemAssetFromASRequest
	pending              map[uint64]chan *hummingbird.RedeemAssetFromASResponse
	requestID            uint64
	mtx                  sync.Mutex
}

func (c *RedemptionServerPeer) Send(req *hummingbird.RedeemAssetFromASRequest) <-chan *hummingbird.RedeemAssetFromASResponse {
	respCh := make(chan *hummingbird.RedeemAssetFromASResponse, 1)
	c.mtx.Lock()
	req.RequestId = c.requestID
	c.requestID++
	c.pending[req.RequestId] = respCh
	c.mtx.Unlock()
	c.sendCh <- req
	return respCh
}

func (c *RedemptionServerPeer) ReturnResponse(msg *hummingbird.RedeemAssetFromASResponse) {
	reqID := msg.RequestId
	c.mtx.Lock()
	defer c.mtx.Unlock()
	ch, ok := c.pending[reqID]
	if ok {
		ch <- msg
		close(ch)
		delete(c.pending, reqID)
	}
}

func (s *Service) DelegateRedemption(ctx context.Context, req *connect.Request[hummingbird.DelegateRedemptionRequest]) (*connect.Response[hummingbird.DelegateRedemptionResponse], error) {
	fmt.Println("DelegateRedemption")
	clientID, ok := ctx.Value("user").(addr.IA)
	if !ok {
		return nil, connect.NewError(connect.CodePermissionDenied, serrors.New("ia not provided"))
	}
	expTime := req.Msg.ExpirationTime.AsTime()
	if expTime.Before(time.Now()) {
		// This is a stop delegate request
		// TODO:
		return nil, connect.NewError(connect.CodeUnimplemented, serrors.New("Case stop delegation not implemented"))
	}
	s.mtx.Lock()
	defer s.mtx.Unlock()
	client, found := s.redemptionServerPeers[clientID]
	var err error
	if !found {
		// redemption server was never connected (since the marketplace was started)
		// which means we have no prior state (except the reservations in the database)
		client = s.newRedemptionServerPeer(clientID)
		s.redemptionServerPeers[clientID] = client
		client.delegatedServer, err = NewRedemptionService(ctx, client, s.store, clientID, RedemptionDelegationUpdate{
			ExpirationTime:     req.Msg.ExpirationTime.AsTime(),
			ReservationIdLimit: req.Msg.ReservationIdUpperBound,
			Key:                req.Msg.Key,
		}, client.sendCh, client.pending)
		if err != nil {

		}

	} else if client.delegatedServer != nil {
		// the redemption server was already delegated, but we received an update request
		// TODO:
		return nil, connect.NewError(connect.CodeUnimplemented, serrors.New("Case redemption delegation update not implemented"))
	} else {
		// the redemption server was previously run by the AS, now it is delegated
		// TODO:
		return nil, connect.NewError(connect.CodeUnimplemented, serrors.New("Case redemption delegation takeover not implemented"))

	}
	client.delegationExpiration = req.Msg.ExpirationTime.AsTime()

	return &connect.Response[hummingbird.DelegateRedemptionResponse]{
		Msg: &hummingbird.DelegateRedemptionResponse{
			ExpirationTime: req.Msg.ExpirationTime,
		},
	}, nil
}

func (c *RedemptionServerPeer) closeConnection() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	close(c.sendCh)
	for _, recvChan := range c.pending {
		close(recvChan)
	}
	c.sendCh = make(chan *hummingbird.RedeemAssetFromASRequest, 64)
}

func (s *Service) RedeemASAsset(ctx context.Context, stream *connect.BidiStream[hummingbird.RedeemAssetFromASResponse, hummingbird.RedeemAssetFromASRequest]) error {
	fmt.Println("RedeemAsset (AS)")
	clientID, ok := ctx.Value("user").(addr.IA)
	if !ok {
		return connect.NewError(connect.CodePermissionDenied, serrors.New("ia not provided"))
	}
	stream.Receive()
	s.mtx.Lock()
	client, found := s.redemptionServerPeers[clientID]
	if !found {
		client = s.newRedemptionServerPeer(clientID)
		s.redemptionServerPeers[clientID] = client
	}
	s.mtx.Unlock()

	fmt.Println("AS redemption service connected:", clientID)

	err := func() error {
		client.mtx.Lock()
		defer client.mtx.Unlock()
		if client.delegatedServer != nil {
			return serrors.New("redemption delegation is active")
		}
		return nil
	}()
	if err != nil {
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
	defer client.closeConnection()

	go func() {
		for req := range client.sendCh {
			if req == nil {
				return
			}
			if err := stream.Send(req); err != nil {
				log.Println("Send error:", err)
				return
			}
		}
	}()

	for {
		msg, err := stream.Receive()
		if err != nil {
			log.Println("Receive error:", err)
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		client.ReturnResponse(msg)
	}
}
