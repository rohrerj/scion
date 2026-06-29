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
	"net/url"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/proto/snap"
	snapconnect "github.com/scionproto/scion/pkg/proto/snap/v1/snapconnect"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type SnapControlClient struct {
	httpClient *http.Client
	token      string
	api        string
	privateKey wgtypes.Key
}

type SnapDataPlane struct {
	Address               string
	SnapTunControlAddress *url.URL
	SnapStaticX25519      []byte
}

// NewSnapControlClient returns a client that can communicate with the SNAP control endpoint.
// It is used by the NewTunnel function, or if the endhost needs to query the DataPlane address
// of the SNAP endpoint.
func NewSnapControlClient(baseURL string, httpClient *http.Client, token string) (*SnapControlClient, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("invalid snap control URL: %w", err)
	}
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	return &SnapControlClient{
		httpClient: httpClient,
		api:        baseURL,
		token:      token,
		privateKey: privateKey,
	}, nil
}

func (c *SnapControlClient) GetDataPlaneAddress(ctx context.Context) (*SnapDataPlane, error) {
	client := snapconnect.NewSnapControlClient(c.httpClient, c.api, connect.WithInterceptors(authInterceptor(c.token)))
	resp, err := client.GetSnapDataPlaneAddress(ctx, connect.NewRequest(&snap.GetSnapDataPlaneRequest{}))
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

func (c *SnapControlClient) registerTunnelIdentity(ctx context.Context, addr string, clientPublicKey []byte, psk []byte) ([]byte, error) {
	if len(psk) != 0 && len(psk) != 32 {
		return nil, fmt.Errorf("psk must be 32 bytes or empty")
	}
	client := snapconnect.NewSnapControlClient(c.httpClient, addr, connect.WithInterceptors(authInterceptor(c.token)))
	req := &snap.RegisterSnapTunIdentityRequest{
		InitiatorStaticX25519: clientPublicKey,
		PskShare:              make([]byte, 32),
	}
	if len(psk) == 32 {
		copy(req.PskShare[0:], psk)
	}
	resp, err := client.RegisterSnapTunIdentity(ctx, &connect.Request[snap.RegisterSnapTunIdentityRequest]{
		Msg: req,
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Msg.PskShare) != 0 && len(resp.Msg.PskShare) != 32 {
		return nil, fmt.Errorf("invalid server psk length: %d", len(resp.Msg.PskShare))
	}
	return resp.Msg.PskShare, nil
}
