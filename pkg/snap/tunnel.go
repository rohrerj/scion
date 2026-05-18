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

	"github.com/rohrerj/scion-over-wireguard/conn"
	"github.com/rohrerj/scion-over-wireguard/device"
	"github.com/rohrerj/scion-over-wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type SnapTunnel struct {
	device        *device.Device
	tnet          *tun.MemoryTun
	DataplaneAddr *net.UDPAddr
	LocalAddr     *net.UDPAddr
}

func NewSnapTunnel(ctx context.Context, snapControlURL string, token string) (*SnapTunnel, error) {
	client, err := newSnapControlClient(snapControlURL, &http.Client{}, token)
	if err != nil {
		return nil, fmt.Errorf("create snap control client: %w", err)
	}

	dp, err := client.getDataPlaneAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("get dataplane address: %w", err)
	}
	clientPublicKey := client.privateKey.PublicKey()
	ownPsk := make([]byte, 32)
	snapTunControlAddr := snapControlURL
	if dp.SnapTunControlAddress != nil {
		snapTunControlAddr = dp.SnapTunControlAddress.String()
	}
	psk, err := client.registerTunnelIdentity(ctx, snapTunControlAddr, clientPublicKey[:], ownPsk)
	if err != nil {
		return nil, fmt.Errorf("register tunnel identity: %w", err)
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", dp.Address)
	if err != nil {
		return nil, fmt.Errorf("resolve endpoint: %w", err)
	}
	tunnel, err := establishWireGuardTunnel(remoteAddr, dp.SnapStaticX25519, client.privateKey[:], psk)
	if err != nil {
		return nil, fmt.Errorf("establish wireguard tunnel: %w", err)
	}

	return tunnel, nil
}

func establishWireGuardTunnel(
	remoteAddr *net.UDPAddr,
	serverPublicKey []byte,
	clientPrivateKey []byte,
	psk []byte,
) (*SnapTunnel, error) {
	memtun := tun.CreateInMemoryTunnel(1000, 1000, 8)
	logger := device.NewLogger(
		device.LogLevelError,
		"snaptun",
	)
	wg := device.NewDevice(
		memtun,
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

		hex.EncodeToString(clientPrivateKey[:]),
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
	handshakeInfo := <-wg.OnHandshakeComplete
	localAddr, err := handshakeInfo.IpSocketAddr.Decode()
	if err != nil {
		return nil, fmt.Errorf("localAddr: %w", err)
	}

	return &SnapTunnel{
		device:        wg,
		tnet:          memtun,
		DataplaneAddr: remoteAddr,
		LocalAddr:     localAddr,
	}, nil
}

func (t *SnapTunnel) Close() error {
	if t.device != nil {
		t.device.Close()
	}
	return nil
}

func (t *SnapTunnel) SendChannel() chan []byte {
	return t.tnet.SendChannel()
}

func (t *SnapTunnel) ReceiveChannel() chan []byte {
	return t.tnet.ReceiveChannel()
}

func (t *SnapTunnel) EventChannel() chan tun.Event {
	return t.tnet.EventChannel()
}
