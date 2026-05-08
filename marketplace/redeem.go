package marketplace

import (
	"context"
	"fmt"
	"log"
	"sync"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
)

func (s *Service) newRedemptionServerPeer(ia addr.IA) *RedemptionServerPeer {
	if s.redemptionServerPeers == nil {
		s.redemptionServerPeers = make(map[addr.IA]*RedemptionServerPeer)
	}
	peer := &RedemptionServerPeer{
		ia:      ia,
		sendCh:  make(chan *hummingbird.RedeemAssetFromASRequest),
		recvCh:  make(chan *hummingbird.RedeemAssetFromASResponse),
		pending: make(map[uint64]chan *hummingbird.RedeemAssetFromASResponse),
	}
	s.redemptionServerPeers[ia] = peer
	return peer
}

type RedemptionServerPeer struct {
	ia     addr.IA
	sendCh chan *hummingbird.RedeemAssetFromASRequest
	recvCh chan *hummingbird.RedeemAssetFromASResponse

	pending   map[uint64]chan *hummingbird.RedeemAssetFromASResponse
	requestID uint64
	mu        sync.Mutex
}

func (c *RedemptionServerPeer) Send(req *hummingbird.RedeemAssetFromASRequest) <-chan *hummingbird.RedeemAssetFromASResponse {
	respCh := make(chan *hummingbird.RedeemAssetFromASResponse, 1)

	c.mu.Lock()
	req.RequestId = c.requestID
	c.requestID++
	c.pending[req.RequestId] = respCh
	c.mu.Unlock()

	c.sendCh <- req

	return respCh
}

func (s *Service) RedeemASAsset(ctx context.Context, stream *connect.BidiStream[hummingbird.RedeemAssetFromASResponse, hummingbird.RedeemAssetFromASRequest]) error {
	fmt.Println("RedeemAsset (AS)")
	user := ctx.Value("user").(string)
	clientID, err := addr.ParseIA(user)
	if err != nil {
		return err
	}
	stream.Receive()
	s.mtx.Lock()
	client, found := s.redemptionServerPeers[clientID]
	if !found {
		client = s.newRedemptionServerPeer(clientID)
		s.redemptionServerPeers[clientID] = client
		fmt.Println("AS client newely registered", "clientID", clientID)
	}
	s.mtx.Unlock()

	fmt.Println("AS client connected:", clientID)

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
			continue
		}

		reqID := msg.RequestId

		client.mu.Lock()
		ch, ok := client.pending[reqID]
		if ok {
			ch <- msg
			close(ch)
			delete(client.pending, reqID)
		}
		client.mu.Unlock()
	}
}
