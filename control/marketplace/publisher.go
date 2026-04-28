package marketplace

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
)

var jwtSecret = []byte("test-key")

func createToken(ia addr.IA) (string, error) {
	claims := jwt.MapClaims{
		"sub":   ia.String(),
		"scope": "PublishAsset",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func authInterceptor(jwtToken string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {

			req.Header().Set("Authorization", "Bearer "+jwtToken)
			return next(ctx, req)
		}
	}
}

type PublishAssetsClient struct {
	MarketplaceUrl string
	IA             addr.IA
	Addr           *net.UDPAddr
}

func (p *PublishAssetsClient) Publish(ctx context.Context, req *hummingbird.PublishAssetRequest) (*hummingbird.PublishAssetResponse, error) {
	fmt.Println("Publish Asset")
	jwtToken, err := createToken(p.IA)
	if err != nil {
		return nil, err
	}
	client := hummingbirdconnect.NewMarketplaceServiceClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}, p.MarketplaceUrl, connect.WithInterceptors(authInterceptor(jwtToken)))
	rep, err := client.PublishAsset(ctx, &connect.Request[hummingbird.PublishAssetRequest]{
		Msg: req,
	})
	if err != nil {
		return nil, err
	}
	return rep.Msg, nil
}
