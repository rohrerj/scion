package marketplace

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
	"golang.org/x/net/http2"
)

type RedemptionClient struct {
	MarketplaceUrl string
	IA             addr.IA
	Addr           *net.UDPAddr
}

func (c *RedemptionClient) Init() {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 5 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP:   c.Addr.IP,
			Zone: c.Addr.Zone,
		},
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     dialer.DialContext,
	}
	http2.ConfigureTransport(tr)

	httpclient := &http.Client{Transport: tr}
	client := hummingbirdconnect.NewRedemptionServiceClient(
		httpclient,
		c.MarketplaceUrl,
	)

	ctx := context.Background()
	time.Sleep(5 * time.Second)
	stream := client.RedeemAsset(ctx)

	fmt.Println("Connected to marketplace")
	err := stream.Send(&hummingbird.RedeemAssetFromASResponse{})
	fmt.Println("send empty", err)
	for {
		msg, err := stream.Receive()
		if err != nil {
			log.Println("Stream error:", err)
			return
		}
		fmt.Println("received redemption request")

		rep := &hummingbird.RedeemAssetFromASResponse{
			Reservation: &hummingbird.ReservationInfo{
				ResId: "my-res-id",
			},
			Ak:        "my-ak",
			MessageId: msg.MessageId,
		}

		if err := stream.Send(rep); err != nil {
			log.Println("Send error:", err)
			return
		}
	}
}
