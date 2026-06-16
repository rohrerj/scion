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
	"google.golang.org/protobuf/types/known/timestamppb"
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
	rep, err := client.DelegateRedemption(ctx, &connect.Request[hummingbird.DelegateRedemptionRequest]{
		Msg: &hummingbird.DelegateRedemptionRequest{
			ExpirationTime:          timestamppb.New(time.Now().Add(time.Second * 30)),
			ReservationIdUpperBound: 1 << 20,
			Key:                     []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			EncodingPoints:          []uint64{100, 250, 500, 1000, 1500, 2000, 2500, 5000, 10000, 20000, 50000, 100000},
		},
	})
	if err != nil {
		return err
	}
	fmt.Println("Redemption delegation until", rep.Msg.ExpirationTime)
	//return nil
	time.Sleep(time.Second * 30)
	stream := client.RedeemASAsset(ctx)

	fmt.Println("Connected to marketplace")
	err = stream.Send(&hummingbird.RedeemAssetFromASResponse{})
	fmt.Println("send empty", err)
	resID := uint32(0)
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
			Ak:        []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			RequestId: msg.RequestId,
		}
		resID++

		if err := stream.Send(rep); err != nil {
			fmt.Println("Send error:", err)
		}
	}
}
