package marketplace

import (
	"context"
	"crypto/tls"
	"fmt"
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
	resID := uint64(0)
	for {
		msg, err := stream.Receive()
		if err != nil {
			fmt.Println("Receive error:", err)
			return err
		}
		fmt.Println("received redemption request")

		rep := &hummingbird.RedeemAssetFromASResponse{
			ResInfo: &hummingbird.ReservationInfo{
				ResId:               resID,
				BwRounded:           1,
				BwDataplaneEncoding: 0xFF,
			},
			Ak:        "my-ak",
			RequestId: msg.RequestId,
		}
		resID++

		if err := stream.Send(rep); err != nil {
			fmt.Println("Send error:", err)
		}
	}
}
