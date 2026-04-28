package marketplace

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
)

func (s *Server) NewRedemptionServerPeer(ia addr.IA, addr string) *RedemptionServerPeer {
	if s.clients == nil {
		s.clients = make(map[string]*RedemptionServerPeer)
	}
	peer := &RedemptionServerPeer{
		ia:     ia,
		sendCh: make(chan *hummingbird.RedeemAssetFromASRequest),
		recvCh: make(chan *hummingbird.RedeemAssetFromASResponse),
	}
	s.clients[addr] = peer
	return peer
}

type RedemptionServerPeer struct {
	ia     addr.IA
	sendCh chan *hummingbird.RedeemAssetFromASRequest
	recvCh chan *hummingbird.RedeemAssetFromASResponse
}

func (c *RedemptionServerPeer) SendAndReceive(req *hummingbird.RedeemAssetFromASRequest) (*hummingbird.RedeemAssetFromASResponse, error) {
	c.sendCh <- req
	fmt.Println("inserted into send channel")
	select {
	case resp := <-c.recvCh:
		fmt.Println("got out of receive channel")
		return resp, nil
	case <-time.After(2 * time.Second):
		return nil, serrors.New("timeout waiting for response")
	}
}

type Server struct {
	clients map[string]*RedemptionServerPeer
}

func (s *Server) RedeemAsset(ctx context.Context, stream *connect.BidiStream[hummingbird.RedeemAssetFromASResponse, hummingbird.RedeemAssetFromASRequest]) error {
	fmt.Println("RedeemAsset (AS)")
	addr, err := net.ResolveUDPAddr("udp", stream.Peer().Addr)
	if err != nil {
		fmt.Println("invalid addr")
		return serrors.New("invalid addr")
	}
	clientID := addr.IP.String()
	client, found := s.clients[clientID]
	if !found {
		fmt.Println("client not registered", "clientID", clientID)
		return serrors.New("client not registered", "clientID", clientID)
	}

	fmt.Println("Client connected:", clientID)

	go func() {
		for {
			fmt.Println("waiting for send channel")
			req := <-client.sendCh
			fmt.Println("got something on send channel")
			if req == nil {
				return
			}
			fmt.Println("send redemption request")
			if err := stream.Send(req); err != nil {
				log.Println("Send error:", err)
				return
			}
			msg, err := stream.Receive()
			if err != nil {
				fmt.Println("Receive error:", err)
				client.recvCh <- nil
				return
			}
			fmt.Println("received redemption response")
			client.recvCh <- msg
		}
	}()
	return nil
}
