package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
)

var jwtSecret = []byte("test-key")

func createToken() (string, error) {
	claims := jwt.MapClaims{
		"sub":   "alice",
		"scope": "SearchAssets,BuyAssets,FetchReservations,RedeemAsset",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

var jwtToken string

func authInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {

			req.Header().Set("Authorization", "Bearer "+jwtToken)
			return next(ctx, req)
		}
	}
}

func main() {
	token, err := createToken()
	if err != nil {
		fmt.Println(err)
		return
	}
	jwtToken = token
	marketUrl := "https://localhost:8888"
	client := hummingbirdconnect.NewMarketplaceServiceClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}, marketUrl, connect.WithInterceptors(authInterceptor()))
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
