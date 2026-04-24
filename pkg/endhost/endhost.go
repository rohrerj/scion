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

package endhost

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/trust"
)

type ConnectOptions func(*connectOptions)
type connectOptions struct {
	// disable tls for all requests
	insecure bool
	// loads trcs from provided folder
	trcDir string
	// the src IP that should be used in the rpc calls
	localIP string
}

// Disables all TLS verifications.
func WithInsecureConnection() ConnectOptions {
	return func(o *connectOptions) {
		o.insecure = true
	}
}

// Loads all TRCs from the provided folder.
func WithTrcDir(dir string) ConnectOptions {
	return func(o *connectOptions) {
		o.trcDir = dir
	}
}

// Uses specified IP when dialing
func WithIP(localIP string) ConnectOptions {
	return func(o *connectOptions) {
		o.localIP = localIP
	}
}

// NewConnector initializes the endhost API connector using the provided api URL.
// When no TRCs are provided, the connector will try to fetch the local ISD TRC from the
// endhost API. However, since the client does not have the trust material to verify the connection
// to the endhost-api server, a man-in-the-middle attacks could theoretically happen.
func NewConnector(ctx context.Context, api string, opts ...ConnectOptions) (*Connector, error) {
	options := &connectOptions{}
	for _, opt := range opts {
		opt(options)
	}
	u, err := url.Parse(api)
	if err != nil {
		return nil, err
	}
	endhostAddr, err := net.ResolveTCPAddr("tcp", u.Host)
	if err != nil {
		return nil, err
	}
	c := &Connector{
		api:        api,
		httpClient: &http.Client{},
	}
	if u.Scheme == "http" {
		options.insecure = true
	}
	trustDB, err := storage.NewInMemoryTrustStorage()
	if err != nil {
		return nil, err
	}
	c.trustDB = trustDB
	var dialContext func(ctx context.Context, network string, address string) (net.Conn, error)
	if options.localIP != "" {
		dialer := &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
			LocalAddr: &net.TCPAddr{
				IP: net.ParseIP(options.localIP),
			},
		}
		dialContext = dialer.DialContext
	}
	if options.insecure {
		// accept any TLS certificate or non-tls connection
		c.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: dialContext,
		}
		c.UnderlayService = c.NewUnderlayService()
		c.Topology, err = c.loadTopology(ctx)
		if err != nil {
			return nil, err
		}
		c.TrustService = c.NewTrustService()
		c.PathService = c.NewPathService()
		c.DRKeyService = c.NewDRKeyService()
		return c, nil
	}
	if options.trcDir != "" {
		// Load TRC from local folder
		trcLoader := trust.TRCLoader{
			Dir: options.trcDir,
			DB:  c.trustDB,
		}
		_, err = trcLoader.Load(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		// We want to use tls but have no local trust root configuration
		// so we can try to retrieve the local ISD TRC from the endhost api.
		// But since we cannot use a TRC to verify the connection to retrieve the TRC,
		// we cannot ensure that a valid TRC is returned.
		c.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: dialContext,
		}
		c.UnderlayService = c.NewUnderlayService()
		c.Topology, err = c.loadTopology(ctx)
		if err != nil {
			return nil, err
		}
		c.TrustService = c.NewTrustService()
		_, err := c.TrustService.TRC(ctx, uint32(c.Topology.LocalIA.ISD()), 0, 0)
		if err != nil {
			return nil, err
		}
	}
	// Now we should have a TRC for the local ISD in the trust store and can
	// initialize the connector properly.
	tlsVerifier := trust.NewTLSCryptoVerifier(c.trustDB)
	c.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			// VerifyConnection requires knowledge of the local IA,
			// which is only available after loading the topology.
			//VerifyConnection:      tlsVerifier.VerifyConnection,
			VerifyPeerCertificate: tlsVerifier.VerifyServerCertificate,
		},
		DialContext: dialContext,
	}
	c.UnderlayService = c.NewUnderlayService()
	c.Topology, err = c.loadTopology(ctx)
	if err != nil {
		return nil, err
	}
	c.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify:    true,
			VerifyConnection:      tlsVerifier.VerifyConnection,
			VerifyPeerCertificate: tlsVerifier.VerifyServerCertificate,
			ServerName: fmt.Sprintf("%s,%s", c.Topology.LocalIA,
				endhostAddr.IP.String()),
		},
		DialContext: dialContext,
	}
	c.TrustService = c.NewTrustService()
	c.PathService = c.NewPathService()
	c.DRKeyService = c.NewDRKeyService()
	return c, nil
}

type Connector struct {
	api             string
	httpClient      *http.Client
	trustDB         storage.TrustDB
	Topology        snet.Topology
	UnderlayService *UnderlayService
	PathService     *PathService
	TrustService    *TrustService
	DRKeyService    *DRKeyService
	// cached values
	underlays  *Underlays
	interfaces map[uint16]netip.AddrPort
}

// loadTopology is called from NewConnector and uses the underlay service to determine the
// available underlays, the local IA and its interfaces and populates a snet.Topology struct.
func (c *Connector) loadTopology(ctx context.Context) (snet.Topology, error) {
	topo := snet.Topology{}
	allUnderlays, err := c.UnderlayService.ListUnderlays(ctx, nil)
	if err != nil {
		return topo, err
	}
	c.underlays = allUnderlays
	// TODO: add support for snap
	if c.underlays.Udp == nil || len(c.underlays.Udp.Routers) == 0 {
		return topo, serrors.New("Local IA cannot be determined without a UDP underlay present")
	}
	// for the moment we just take the first router to determine the local IA
	firstRouter := c.underlays.Udp.Routers[0]
	topo.LocalIA = addr.IA(firstRouter.IsdAs)
	topo.PortRange = snet.TopologyPortRange{
		Start: uint16(firstRouter.DispatchedPortStart),
		End:   uint16(firstRouter.DispatchedPortEnd),
	}
	c.interfaces = make(map[uint16]netip.AddrPort)
	for _, router := range c.underlays.Udp.Routers {
		addr, err := netip.ParseAddrPort(router.Address)
		if err != nil {
			return topo, err
		}
		for _, inf := range router.Interfaces {
			c.interfaces[uint16(inf)] = addr
		}
	}
	topo.Interface = func(u uint16) (netip.AddrPort, bool) {
		addr, ok := c.interfaces[u]
		return addr, ok
	}
	return topo, nil
}
