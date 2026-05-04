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
)

type SnapControlClient struct {
	client snapconnect.SnapControlClient
}

type SnapDataPlane struct {
	Address               string
	SnapTunControlAddress *url.URL
	SnapStaticX25519      []byte
}

func NewSnapControlClient(baseURL string, httpClient *http.Client) (*SnapControlClient, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("invalid snap control URL: %w", err)
	}
	client := snapconnect.NewSnapControlClient(httpClient, baseURL)
	return &SnapControlClient{client: client}, nil
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

func Init(ctx context.Context, snapControlAddr string) {
	tunnel, err := InitSnapTunnel(ctx, snapControlAddr, net.IPv4(192, 168, 100, 1), net.IPv4(192, 168, 100, 2))
	if err != nil {
		panic(err)
	}
	defer tunnel.Close()

	payload := []byte("example SCION packet bytes")
	if err := tunnel.SendPacket(payload); err != nil {
		panic(err)
	}
}
