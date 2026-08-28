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

package marketplace_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/marketplace"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
)

// TestQueueRedemptionRequestWithoutRedemptionServer checks that without a delegation
// and without a connected redemption server, the request is refused.
func TestQueueRedemptionRequestWithoutRedemptionServer(t *testing.T) {
	h := newHandler()
	resp := waitForResponse(t, h.QueueRedemptionRequest(&hummingbird.RedeemAssetFromASRequest{}))
	assert.NotEmpty(t, resp.GetError())
}

// TestQueueRedemptionRequestReachesTheRedemptionServer checks that with a non-delegated,
// AS redemption server connected to the service, a request is queued and stays unanswered
// until that server replies with the matching request id.
func TestQueueRedemptionRequestReachesTheRedemptionServer(t *testing.T) {
	h := newHandler()
	conn := h.AttachRemote(func() {})

	reply := h.QueueRedemptionRequest(&hummingbird.RedeemAssetFromASRequest{Bandwidth: 100})
	req := waitForRequest(t, conn)
	assert.NotZero(t, req.RequestId, "the handler must assign a request id to correlate the reply")
	assert.Equal(t, uint32(100), req.Bandwidth)

	select {
	case <-reply:
		t.Fatal("the request was answered before the redemption server replied")
	default:
	}

	h.DeliverRedemptionResponse(&hummingbird.RedeemAssetFromASResponse{
		RequestId: req.RequestId,
		Result: &hummingbird.RedeemAssetFromASResponse_ResInfo{
			ResInfo: &hummingbird.ReservationInfo{ReservationId: 7},
		},
	})
	resp := waitForResponse(t, reply)
	assert.Equal(t, uint32(7), resp.GetResInfo().GetReservationId())
}

// TestDeliverUnknownRedemptionResponse checks that a response nobody is waiting for
// is dropped rather than blocking the caller.
func TestDeliverUnknownRedemptionResponse(t *testing.T) {
	h := newHandler()
	h.DeliverRedemptionResponse(&hummingbird.RedeemAssetFromASResponse{RequestId: 42})
}

// TestDetachRemoteRefusesPendingRequests checks that when the AS redemption server disconnects,
// the requests it didn't answered yet are refused.
func TestDetachRemoteRefusesPendingRequests(t *testing.T) {
	h := newHandler()
	conn := h.AttachRemote(func() {})
	reply := h.QueueRedemptionRequest(&hummingbird.RedeemAssetFromASRequest{})
	waitForRequest(t, conn)

	h.DetachRemote(conn)
	assert.NotEmpty(t, waitForResponse(t, reply).GetError())

	// With nothing connected any more, later requests are refused too.
	assert.NotEmpty(t,
		waitForResponse(t, h.QueueRedemptionRequest(&hummingbird.RedeemAssetFromASRequest{})).GetError())
}

// TestAttachRemoteReplacesTheOpenConnection checks that a reconnecting redemption server
// replaces the open connection:
// The requests of the old one are refused, and detaching the old stale connection afterwards
// must leave the new one in place.
func TestAttachRemoteReplacesTheOpenConnection(t *testing.T) {
	h := newHandler()
	firstCancelled := make(chan struct{})
	first := h.AttachRemote(func() { close(firstCancelled) })
	reply := h.QueueRedemptionRequest(&hummingbird.RedeemAssetFromASRequest{})
	waitForRequest(t, first)

	second := h.AttachRemote(func() {})
	assert.NotEmpty(t, waitForResponse(t, reply).GetError(),
		"a request handed to the replaced connection can never be answered")
	select {
	case <-firstCancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the replaced connection was not cancelled")
	}

	// The stale connection must not detach the one that replaced it.
	h.DetachRemote(first)
	h.QueueRedemptionRequest(&hummingbird.RedeemAssetFromASRequest{})
	waitForRequest(t, second)
}

// TestCloseRedemptionServerConnection checks that CloseRedemptionServerConnection does not
// deadlock against the handler. It must return, and cancel the stream serving the connection.
func TestCloseRedemptionServerConnection(t *testing.T) {
	h := newHandler()
	cancelled := make(chan struct{})
	conn := h.AttachRemote(func() { close(cancelled) })
	reply := h.QueueRedemptionRequest(&hummingbird.RedeemAssetFromASRequest{})
	waitForRequest(t, conn)

	returned := make(chan struct{})
	go func() {
		h.CloseRedemptionServerConnection()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("CloseRedemptionServerConnection did not return")
	}

	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection was not cancelled")
	}
	assert.NotEmpty(t, waitForResponse(t, reply).GetError())

	// Closing again, and detaching the closed connection, must both be harmless.
	h.CloseRedemptionServerConnection()
	h.DetachRemote(conn)
}

// TestQueueRedemptionRequestOnAFullQueueOfAClosingConnection checks that a request
// handed over while the connection is going away, is refused once the queue is full.
func TestQueueRedemptionRequestOnAFullQueueOfAClosingConnection(t *testing.T) {
	h := newHandler()
	conn := h.AttachRemote(func() {})
	// Fill the queue without draining it, so that the next hand-over blocks.
	for i := 0; i < 128; i++ {
		h.QueueRedemptionRequest(&hummingbird.RedeemAssetFromASRequest{})
	}
	blocked := make(chan *hummingbird.RedeemAssetFromASResponse, 1)
	go func() {
		blocked <- waitForResponse(t, h.QueueRedemptionRequest(
			&hummingbird.RedeemAssetFromASRequest{}))
	}()
	// Nothing drains the queue, so the hand-over is still waiting. Detaching the
	// connection has to release it.
	h.DetachRemote(conn)
	select {
	case resp := <-blocked:
		assert.NotEmpty(t, resp.GetError())
	case <-time.After(5 * time.Second):
		t.Fatal("a request waiting on a full queue was not released by the detach")
	}
}

// newHandler builds a handler without a store. Only ApplyDelegation reaches the
// store, and these tests exercise the routing towards the redemption server of
// the AS instead.
func newHandler() *marketplace.RedemptionServerHandler {
	return marketplace.NewRedemptionServerHandler(addr.MustParseIA("1-ff00:0:110"), nil)
}

// waitForRequest returns the request the handler routed to a connection.
func waitForRequest(
	t *testing.T,
	conn *marketplace.RemoteConn,
) *hummingbird.RedeemAssetFromASRequest {
	t.Helper()
	select {
	case req := <-conn.Out():
		require.NotNil(t, req)
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not route the request to this connection")
		return nil
	}
}

func waitForResponse(
	t *testing.T,
	reply <-chan *hummingbird.RedeemAssetFromASResponse,
) *hummingbird.RedeemAssetFromASResponse {
	t.Helper()
	select {
	case resp := <-reply:
		require.NotNil(t, resp)
		return resp
	case <-time.After(5 * time.Second):
		t.Fatal("the request was never answered")
		return nil
	}
}
