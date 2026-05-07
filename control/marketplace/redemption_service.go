package marketplace

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
	"golang.org/x/net/http2"
)

type RedemptionClient struct {
	MarketplaceUrl string
	IA             addr.IA
	Token          *JwtToken
}

func (c *RedemptionClient) Init() error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	http2.ConfigureTransport(tr)

	httpclient := &http.Client{Transport: tr}
	client := hummingbirdconnect.NewRedemptionServiceClient(
		httpclient,
		c.MarketplaceUrl,
		connect.WithInterceptors(NewAuthInterceptor(c.Token)),
	)
	for c.Token.String() == "" {
		time.Sleep(5 * time.Second)
	}

	ctx := context.Background()
	stream := client.RedeemASAsset(ctx)

	fmt.Println("Connected to marketplace")
	err := stream.Send(&hummingbird.RedeemAssetFromASResponse{})
	fmt.Println("send empty", err)
	for {
		msg, err := stream.Receive()
		if err != nil {
			log.Println("Receive error:", err)
		}
		fmt.Println("received redemption request")

		rep := &hummingbird.RedeemAssetFromASResponse{
			Reservation: &hummingbird.ReservationInfo{
				ResId: "my-res-id",
			},
			Ak:        "my-ak",
			RequestId: msg.RequestId,
		}

		if err := stream.Send(rep); err != nil {
			log.Println("Send error:", err)
		}
	}
}
