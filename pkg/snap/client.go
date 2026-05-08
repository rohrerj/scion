// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package snap

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/proto/snap"
	snapconnect "github.com/scionproto/scion/pkg/proto/snap/v1/snapconnect"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type SnapControlClient struct {
	client     snapconnect.SnapControlClient
	token      string
	api        string
	privateKey wgtypes.Key
}

type SnapDataPlane struct {
	Address               string
	SnapTunControlAddress *url.URL
	SnapStaticX25519      []byte
}

func newSnapControlClient(baseURL string, httpClient *http.Client, token string) (*SnapControlClient, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("invalid snap control URL: %w", err)
	}
	client := snapconnect.NewSnapControlClient(httpClient, baseURL, connect.WithInterceptors(authInterceptor(token)))
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	return &SnapControlClient{
		client:     client,
		api:        baseURL,
		token:      token,
		privateKey: privateKey,
	}, nil
}

func (c *SnapControlClient) GetDataPlaneAddress(ctx context.Context) (*SnapDataPlane, error) {
	resp, err := c.client.GetSnapDataPlaneAddress(ctx, connect.NewRequest(&snap.GetSnapDataPlaneRequest{}))
	if err != nil {
		return nil, fmt.Errorf("get dataplane address failed: %w", err)
	}

	result := &SnapDataPlane{
		Address:          resp.Msg.Address,
		SnapStaticX25519: resp.Msg.SnapStaticX25519,
	}

	if resp.Msg.SnapTunControlAddress != nil && *resp.Msg.SnapTunControlAddress != "" {
		parsed, err := url.Parse(*resp.Msg.SnapTunControlAddress)
		if err != nil {
			addr, parseErr := net.ResolveUDPAddr("udp", *resp.Msg.SnapTunControlAddress)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid snap-tun control address %q: %w / %v", *resp.Msg.SnapTunControlAddress, err, parseErr)
			}
			parsed = &url.URL{
				Scheme: "http",
				Host:   addr.String(),
			}
		}
		result.SnapTunControlAddress = parsed
	}

	return result, nil
}

func (c *SnapControlClient) RegisterSnapTunIdentity(ctx context.Context, req *connect.Request[snap.RegisterSnapTunIdentityRequest]) (*connect.Response[snap.RegisterSnapTunIdentityResponse], error) {
	return c.client.RegisterSnapTunIdentity(ctx, req)
}

func Init(ctx context.Context, snapControlAddr string, token string) {
	tunnel, err := InitSnapTunnel(ctx, snapControlAddr, token, netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		panic(err)
	}
	defer tunnel.Close()

	payload := []byte("example SCION packet bytes")
	if err := tunnel.SendPacket(payload, 8888); err != nil {
		panic(err)
	}
}
