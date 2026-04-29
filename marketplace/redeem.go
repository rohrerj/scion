package marketplace

import (
	"context"
	"fmt"
	"log"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
)

func (s *Server) NewRedemptionServerPeer(ia addr.IA) *RedemptionServerPeer {
	if s.clients == nil {
		s.clients = make(map[addr.IA]*RedemptionServerPeer)
	}
	peer := &RedemptionServerPeer{
		ia:     ia,
		sendCh: make(chan *hummingbird.RedeemAssetFromASRequest),
		recvCh: make(chan *hummingbird.RedeemAssetFromASResponse),
	}
	s.clients[ia] = peer
	return peer
}

type RedemptionServerPeer struct {
	ia     addr.IA
	sendCh chan *hummingbird.RedeemAssetFromASRequest
	recvCh chan *hummingbird.RedeemAssetFromASResponse
}

func (c *RedemptionServerPeer) SendAndReceive(req *hummingbird.RedeemAssetFromASRequest) (*hummingbird.RedeemAssetFromASResponse, error) {
	select {
	case c.sendCh <- req:
	default:
		return nil, serrors.New("could not insert into queue")
	}

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
	clients map[addr.IA]*RedemptionServerPeer
}

func (s *Server) RedeemAsset(ctx context.Context, stream *connect.BidiStream[hummingbird.RedeemAssetFromASResponse, hummingbird.RedeemAssetFromASRequest]) error {
	fmt.Println("RedeemAsset (AS)")
	user := ctx.Value("user").(string)
	clientID, err := addr.ParseIA(user)
	if err != nil {
		return err
	}
	stream.Receive()
	client, found := s.clients[clientID]
	if !found {
		fmt.Println("client not registered", "clientID", clientID)
		return serrors.New("client not registered", "clientID", clientID)
	}

	fmt.Println("Client connected:", clientID)

	for {
		fmt.Println("waiting for send channel")
		req := <-client.sendCh
		fmt.Println("got something on send channel", clientID)
		if req == nil {
			return nil
		}
		fmt.Println("send redemption request")
		if err := stream.Send(req); err != nil {
			log.Println("Send error:", err)
			return err
		}
		msg, err := stream.Receive()
		if err != nil {
			fmt.Println("Receive error:", err)
			client.recvCh <- nil
			return err
		}
		fmt.Println("received redemption response")
		client.recvCh <- msg
	}
}
