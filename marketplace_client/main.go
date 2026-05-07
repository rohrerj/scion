package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
)

func authInterceptor(jwtToken string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("Authorization", "Bearer "+jwtToken)
			return next(ctx, req)
		}
	}
}

func main() {
	args := os.Args
	if len(args) != 2 {
		fmt.Println("Provide JWT token as command line argument. Requested at: https://localhost:8889")
		return
	}
	jwtToken := args[1]
	marketUrl := "https://localhost:8888"
	client := hummingbirdconnect.NewMarketplaceServiceClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}, marketUrl, connect.WithInterceptors(authInterceptor(jwtToken)))
	ctx := context.Background()
	infoRep, err := client.Info(ctx, &connect.Request[hummingbird.MarketplaceInfoRequest]{})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("info", infoRep.Msg.String())
	targetIA := uint64(addr.MustParseIA("1-ff00:0:110"))
	searchAssetRep, err := client.SearchAssets(ctx, &connect.Request[hummingbird.SearchAssetsRequest]{
		Msg: &hummingbird.SearchAssetsRequest{
			Owned: false,
			Ia:    &targetIA,
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("searched assets", searchAssetRep.Msg.String())
	if len(searchAssetRep.Msg.Assets) == 0 {
		fmt.Println("no assets found")
		return
	}
	boughtAssets, err := client.BuyAssets(ctx, &connect.Request[hummingbird.BuyAssetsRequest]{
		Msg: &hummingbird.BuyAssetsRequest{
			Assets: []*hummingbird.BuyAsset{
				{
					AssetId: searchAssetRep.Msg.Assets[0].AssetId,
				},
			},
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("bought assets:", boughtAssets.Msg.String())
	if len(boughtAssets.Msg.Assets) == 0 {
		fmt.Println("no assets bought")
		return
	}

	redeemedAssets, err := client.RedeemAsset(ctx, &connect.Request[hummingbird.RedeemAssetRequest]{
		Msg: &hummingbird.RedeemAssetRequest{
			IngressAssetId: boughtAssets.Msg.Assets[0].AssetId,
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("redeemed assets:", redeemedAssets.Msg.String())
}
