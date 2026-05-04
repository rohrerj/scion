package snap

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"net/url"

	"connectrpc.com/connect"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/scionproto/scion/pkg/proto/snap"
)

type SnapTunnel struct {
	device    *device.Device
	tun       *netstack.Net
	remoteTun net.IP
}

func InitSnapTunnel(ctx context.Context, snapControlURL string, localTunIP, remoteTunIP net.IP) (*SnapTunnel, error) {
	client, err := NewSnapControlClient(snapControlURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create snap control client: %w", err)
	}

	dp, err := client.GetDataPlaneAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("get dataplane address: %w", err)
	}

	tunnel, err := client.establishWireGuardTunnel(ctx, dp, localTunIP, remoteTunIP)
	if err != nil {
		return nil, fmt.Errorf("establish wireguard tunnel: %w", err)
	}

	return tunnel, nil
}

func (c *SnapControlClient) establishWireGuardTunnel(ctx context.Context, dp *SnapDataPlane, localTunIP, remoteTunIP net.IP) (*SnapTunnel, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", dp.Address)
	if err != nil {
		return nil, fmt.Errorf("parse dataplane address: %w", err)
	}

	localAddr := netip.AddrFrom4([4]byte(localTunIP.To4()))
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{localAddr}, nil, 1420)
	if err != nil {
		return nil, fmt.Errorf("create TUN device: %w", err)
	}

	bind := conn.NewDefaultBind()
	wgDevice := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelVerbose, "wireguard"))

	privateKey, err := generateWireGuardKey()
	if err != nil {
		wgDevice.Close()
		return nil, fmt.Errorf("generate private key: %w", err)
	}

	if len(dp.SnapStaticX25519) != 32 {
		wgDevice.Close()
		return nil, fmt.Errorf("server static key length %d", len(dp.SnapStaticX25519))
	}
	var peerKey wgtypes.Key
	copy(peerKey[:], dp.SnapStaticX25519)

	config := fmt.Sprintf(
		"private_key=%s\npeer=%s\nendpoint=%s\npersistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\n",
		privateKey.String(),
		peerKey.String(),
		remoteAddr.String(),
	)
	if err := wgDevice.IpcSet(config); err != nil {
		wgDevice.Close()
		return nil, fmt.Errorf("set device config: %w", err)
	}

	if dp.SnapTunControlAddress != nil {
		if err := c.registerTunnelIdentity(ctx, dp.SnapTunControlAddress, privateKey); err != nil {
			wgDevice.Close()
			return nil, fmt.Errorf("register tunnel identity: %w", err)
		}
	}

	if err := wgDevice.Up(); err != nil {
		wgDevice.Close()
		return nil, fmt.Errorf("bring up wireguard device: %w", err)
	}

	return &SnapTunnel{
		device:    wgDevice,
		tun:       tnet,
		remoteTun: remoteTunIP,
	}, nil
}

func (t *SnapTunnel) SendPacket(payload []byte) error {
	conn, err := t.tun.DialUDP(nil, &net.UDPAddr{IP: t.remoteTun, Port: 0})
	if err != nil {
		return fmt.Errorf("dial through tunnel: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(payload)
	if err != nil {
		return fmt.Errorf("write to tunnel: %w", err)
	}
	return nil
}

func (t *SnapTunnel) Close() error {
	if t.device != nil {
		t.device.Close()
	}
	return nil
}

func generateWireGuardKey() (wgtypes.Key, error) {
	var key wgtypes.Key
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return key, err
	}
	copy(key[:], b)
	return key, nil
}

func (c *SnapControlClient) registerTunnelIdentity(ctx context.Context, tunnelControlURL *url.URL, privateKey wgtypes.Key) error {
	tunnelClient, err := NewSnapControlClient(tunnelControlURL.String(), nil)
	if err != nil {
		return fmt.Errorf("create tunnel control client: %w", err)
	}

	var x25519Private [32]byte
	copy(x25519Private[:], privateKey[:])

	var initiatorPublic [32]byte
	curve25519.ScalarBaseMult(&initiatorPublic, &x25519Private)

	req := connect.NewRequest(&snap.RegisterSnapTunIdentityRequest{
		InitiatorStaticX25519: initiatorPublic[:],
		PskShare:              make([]byte, 32),
	})

	_, err = tunnelClient.RegisterSnapTunIdentity(ctx, req)
	if err != nil {
		return fmt.Errorf("register snap-tun identity RPC failed: %w", err)
	}
	return nil
}
