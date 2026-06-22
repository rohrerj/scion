package marketplace

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
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
	//var err error
	//return nil
	/*
		stream := client.RedeemASAsset(ctx)

		fmt.Println("Connected to marketplace")
		err = stream.Send(&hummingbird.RedeemAssetFromASResponse{})
		fmt.Println("send empty", err)
		resID := uint32(0)
		go func() {
			for {
				msg, err := stream.Receive()
				if err != nil {
					fmt.Println("Receive error:", err)
					return
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
		}()*/
	var step = math.Pow(10_000_000.0/100.0, 1.0/float64(1024-1))

	// For some DP encoding i, return the corresponding bandwidth in kbps.
	indexToBwKbps := func(i int) int {
		bw := 100.0 * math.Pow(step, float64(i))
		return int(math.Ceil(bw))
	}
	encodings := make([]uint32, 1024)
	for i := 0; i < 1024; i++ {
		encodings[i] = uint32(indexToBwKbps(i))
	}
	startDelegation := func(exp time.Time) error {
		rep, err := client.DelegateRedemption(ctx, &connect.Request[hummingbird.DelegateRedemptionRequest]{
			Msg: &hummingbird.DelegateRedemptionRequest{
				ExpirationTime:          timestamppb.New(exp),
				ReservationIdUpperBound: 1 << 20,
				Key:                     []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
				EncodingPoints:          encodings,
			},
		})
		if err != nil {
			return err
		}
		fmt.Println("Redemption delegation until", rep.Msg.ExpirationTime)
		return nil
	}
	connectAsRedemptionService := func() error {
		var err error
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
					ReservationId:       resID,
					BandwithRounded:     1,
					BwDataplaneEncoding: 0xFF,
				},
				AuthenticationKey: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
				RequestId:         msg.RequestId,
			}
			resID++

			if err := stream.Send(rep); err != nil {
				fmt.Println("Send error:", err)
			}
		}
	}
	for i := 0; i < 10; i++ {
		err := connectAsRedemptionService()
		if err != nil {
			fmt.Println(err)
		}
		time.Sleep(time.Minute)
	}

	time.Sleep(time.Hour * 24 * 6)
	startDelegation(time.Now().Add(time.Hour * 24 * 7))
	time.Sleep(time.Hour * 24 * 6)
	connectAsRedemptionService()
	/*time.Sleep(time.Second * 10)
	startDelegation(time.Now().Add(time.Second * 10))
	time.Sleep(time.Second * 20)
	connectAsRedemptionService()
	time.Sleep(time.Second * 10)
	startDelegation(time.Time{})
	time.Sleep(time.Second * 10)
	connectAsRedemptionService()*/
	return nil
}
