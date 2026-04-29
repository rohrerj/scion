package marketplace

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
)

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
	}, p.MarketplaceUrl, connect.WithInterceptors(NewAuthInterceptor(jwtToken)))
	rep, err := client.PublishAsset(ctx, &connect.Request[hummingbird.PublishAssetRequest]{
		Msg: req,
	})
	if err != nil {
		return nil, err
	}
	return rep.Msg, nil
}
