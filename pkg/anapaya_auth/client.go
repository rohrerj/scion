package anapayaauth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/proto/aa"
	"github.com/scionproto/scion/pkg/proto/aa/v1/aaconnect"
)

type Client struct {
	client    aaconnect.AuthServiceClient
	apiKey    string
	token     string
	lastFetch time.Time
}

func NewClient(key string) *Client {
	const api = "https://auth.scion.anapaya.net"
	return &Client{
		client: aaconnect.NewAuthServiceClient(http.DefaultClient, api),
		apiKey: key,
	}
}

func (c *Client) Token() string {
	if time.Since(c.lastFetch) > time.Minute*10 {
		token, err := c.authenticate(context.TODO())
		if err != nil {
			fmt.Println(err)
		} else {
			c.token = token
		}
	}
	return c.token
}

func (c *Client) authenticate(ctx context.Context) (string, error) {
	rep, err := c.client.AuthenticateByKey(ctx, &connect.Request[aa.AuthenticateByKeyRequest]{
		Msg: &aa.AuthenticateByKeyRequest{
			ApiKey: c.apiKey,
		},
	})
	if err != nil {
		return "", err
	}
	return rep.Msg.SnapToken, nil
}
