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
	"encoding/hex"
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
	device *device.Device
	net    *netstack.Net
}

func NewSnapTunnel(ctx context.Context, snapControlURL string, token string, localTunIP netip.Addr) (*SnapTunnel, error) {
	client, err := newSnapControlClient(snapControlURL, &http.Client{}, token)
	if err != nil {
		return nil, fmt.Errorf("create snap control client: %w", err)
	}

	dp, err := client.GetDataPlaneAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("get dataplane address: %w", err)
	}
	/*dp := &SnapDataPlane{
		Address:          "127.0.0.100:5001",
		SnapStaticX25519: []byte{47, 229, 125, 163, 71, 205, 98, 67, 21, 40, 218, 172, 95, 187, 41, 7, 48, 255, 246, 132, 175, 196, 207, 194, 237, 144, 153, 95, 88, 203, 59, 116},
	}*/
	fmt.Println("dp", dp)
	clientPublicKey := client.privateKey.PublicKey()
	ownPsk := make([]byte, 32)
	psk, err := client.registerTunnelIdentity(ctx, clientPublicKey[:], ownPsk)
	if err != nil {
		return nil, fmt.Errorf("register tunnel identity: %w", err)
	}
	fmt.Println("psk", psk)

	remoteAddr, err := net.ResolveUDPAddr("udp", dp.Address)
	if err != nil {
		return nil, fmt.Errorf("resolve endpoint: %w", err)
	}
	tunnel, err := client.establishWireGuardTunnel(localTunIP, remoteAddr, dp.SnapStaticX25519, psk)
	if err != nil {
		return nil, fmt.Errorf("establish wireguard tunnel: %w", err)
	}

	return tunnel, nil
}

func (c *SnapControlClient) establishWireGuardTunnel(
	localTunIP netip.Addr,
	remoteAddr *net.UDPAddr,
	serverPublicKey []byte,
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
	var pskKey wgtypes.Key
	copy(pskKey[:], psk)

	config := fmt.Sprintf(
		"private_key=%s\n"+
			"replace_peers=true\n"+
			"public_key=%s\n"+
			//"preshared_key=%s\n"+
			"endpoint=%s\n"+
			"persistent_keepalive_interval=10\n"+
			"allowed_ip=0.0.0.0/0\n",

		hex.EncodeToString(c.privateKey[:]),
		hex.EncodeToString(serverPublicKey[:]),
		//hex.EncodeToString(pskKey[:]),
		remoteAddr.String(),
	)

	if err := wg.IpcSet(config); err != nil {
		wg.Close()
		return nil, fmt.Errorf("ipc set: %w", err)
	}
	if err := wg.Up(); err != nil {
		wg.Close()
		return nil, fmt.Errorf("device up: %w", err)
	}
	dump, _ := wg.IpcGet()
	fmt.Println("AFTER IPCSET:")
	fmt.Println(dump)

	return &SnapTunnel{
		device: wg,
		net:    tnet,
	}, nil
}

func (t *SnapTunnel) Close() error {
	if t.device != nil {
		t.device.Close()
	}
	return nil
}

func (t *SnapTunnel) Metrics() (string, error) {
	state, err := t.device.IpcGet()
	if err != nil {
		return "", err
	}
	return state, nil
}

func (t *SnapTunnel) ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error) {
	conn, err := t.net.ListenUDP(laddr)
	return conn, err
}

func (t *SnapTunnel) DialUDP(laddr *net.UDPAddr, raddr *net.UDPAddr) (net.Conn, error) {
	conn, err := t.net.DialUDP(laddr, raddr)
	return conn, err
}

func (c *SnapControlClient) registerTunnelIdentity(ctx context.Context, clientPublicKey []byte, psk []byte) ([]byte, error) {
	if len(psk) != 0 && len(psk) != 32 {
		return nil, fmt.Errorf("psk must be 32 bytes or empty")
	}
	fmt.Println("client pk", clientPublicKey)
	req := &snap.RegisterSnapTunIdentityRequest{
		InitiatorStaticX25519: clientPublicKey,
		PskShare:              make([]byte, 32),
	}
	if len(psk) == 32 {
		copy(req.PskShare[0:], psk)
	}
	fmt.Println("req psk", req.PskShare)
	resp, err := c.client.RegisterSnapTunIdentity(ctx, &connect.Request[snap.RegisterSnapTunIdentityRequest]{
		Msg: req,
	})
	if err != nil {
		return nil, err
	}
	fmt.Println("registerTunnelIdentity resp", resp)
	if len(resp.Msg.PskShare) != 0 && len(resp.Msg.PskShare) != 32 {
		return nil, fmt.Errorf("invalid server psk length: %d", len(resp.Msg.PskShare))
	}
	fmt.Println("rep psk", resp.Msg.PskShare)
	return resp.Msg.PskShare, nil
}
