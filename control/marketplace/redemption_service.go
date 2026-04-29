package marketplace

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
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
	Addr           *net.UDPAddr
}

func (c *RedemptionClient) Init() error {
	jwtToken, err := createToken(c.IA)
	if err != nil {
		return err
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	http2.ConfigureTransport(tr)

	httpclient := &http.Client{Transport: tr}
	client := hummingbirdconnect.NewRedemptionServiceClient(
		httpclient,
		c.MarketplaceUrl,
		connect.WithInterceptors(NewAuthInterceptor(jwtToken)),
	)

	ctx := context.Background()
	time.Sleep(5 * time.Second)
	stream := client.RedeemAsset(ctx)

	fmt.Println("Connected to marketplace")
	err = stream.Send(&hummingbird.RedeemAssetFromASResponse{})
	fmt.Println("send empty", err)
	for {
		msg, err := stream.Receive()
		if err != nil {
			log.Println("Stream error:", err)
			return err
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
			return err
		}
	}
}
