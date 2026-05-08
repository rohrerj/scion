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
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/netip"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/proto/snap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type SnapTunnel struct {
	device   *device.Device
	net      *netstack.Net
	remoteIP net.IP
}

func InitSnapTunnel(ctx context.Context, snapControlURL string, token string, localTunIP netip.Addr) (*SnapTunnel, error) {
	client, err := newSnapControlClient(snapControlURL, &http.Client{}, token)
	if err != nil {
		return nil, fmt.Errorf("create snap control client: %w", err)
	}

	dp, err := client.GetDataPlaneAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("get dataplane address: %w", err)
	}
	clientPublicKey := client.privateKey.PublicKey()
	psk, err := client.registerTunnelIdentity(ctx, clientPublicKey[:], nil)
	if err != nil {
		return nil, fmt.Errorf("register tunnel identity: %w", err)
	}

	var peerKey wgtypes.Key
	copy(peerKey[:], dp.SnapStaticX25519)
	remoteAddr, err := net.ResolveUDPAddr("udp", dp.Address)
	if err != nil {
		return nil, fmt.Errorf("resolve endpoint: %w", err)
	}
	tunnel, err := client.establishWireGuardTunnel(localTunIP, remoteAddr, peerKey, psk)
	if err != nil {
		return nil, fmt.Errorf("establish wireguard tunnel: %w", err)
	}

	return tunnel, nil
}

func (c *SnapControlClient) establishWireGuardTunnel(
	localTunIP netip.Addr,
	remoteAddr *net.UDPAddr,
	serverKey wgtypes.Key,
	psk []byte,
) (*SnapTunnel, error) {

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{localTunIP},
		nil,
		1420,
	)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}

	logger := device.NewLogger(
		device.LogLevelVerbose,
		"snaptun",
	)

	wg := device.NewDevice(
		tun,
		conn.NewDefaultBind(),
		logger,
	)

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		wg.Close()
		return nil, err
	}

	config := fmt.Sprintf(`
private_key=%s
replace_peers=true

public_key=%s
endpoint=%s
persistent_keepalive_interval=10

allowed_ip=0.0.0.0/0
`,
		privateKey.String(),
		serverKey.String(),
		remoteAddr.String(),
	)
	if len(psk) == 32 {
		config += fmt.Sprintf(
			"\npreshared_key=%s\n",
			base64.StdEncoding.EncodeToString(psk),
		)
	}

	if err := wg.IpcSet(config); err != nil {
		wg.Close()
		return nil, fmt.Errorf("ipc set: %w", err)
	}

	if err := wg.Up(); err != nil {
		wg.Close()
		return nil, fmt.Errorf("device up: %w", err)
	}

	return &SnapTunnel{
		device:   wg,
		net:      tnet,
		remoteIP: net.ParseIP("10.0.0.1"),
	}, nil
}

func (t *SnapTunnel) Close() error {
	if t.device != nil {
		t.device.Close()
	}
	return nil
}

func (t *SnapTunnel) SendPacket(
	payload []byte,
	port int,
) error {

	conn, err := t.net.DialUDP(nil, &net.UDPAddr{
		IP:   t.remoteIP,
		Port: port,
	})
	if err != nil {
		return fmt.Errorf("dial udp: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(payload)
	if err != nil {
		return fmt.Errorf("write udp: %w", err)
	}

	return nil
}

func (c *SnapControlClient) registerTunnelIdentity(ctx context.Context, clientPublicKey []byte, psk []byte) ([]byte, error) {
	if len(psk) != 0 && len(psk) != 32 {
		return nil, fmt.Errorf("psk must be 32 bytes or empty")
	}
	req := &snap.RegisterSnapTunIdentityRequest{
		InitiatorStaticX25519: clientPublicKey,
		PskShare:              make([]byte, 32),
	}
	if len(psk) == 32 {
		copy(req.PskShare, psk)
	}
	resp, err := c.client.RegisterSnapTunIdentity(ctx, &connect.Request[snap.RegisterSnapTunIdentityRequest]{
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
