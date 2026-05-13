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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"

	"connectrpc.com/connect"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/storage"
	db "github.com/scionproto/scion/private/storage/trust/memory"
	"github.com/scionproto/scion/private/trust"
)

type ConnectOption func(*connectOptions)
type connectOptions struct {
	// disable tls for all requests
	insecure bool
	// loads trcs from provided folder
	trcDir          string
	localIA         addr.IA
	localIASelector func([]addr.IA) addr.IA
	// tls client certificate, might be required for drkey requests
	tlsCertificate *tls.Certificate
	token          string
}

// Disables all TLS verifications. Implies allow insecure.
func WithInsecureConnection() ConnectOption {
	return func(o *connectOptions) {
		o.insecure = true
	}
}

// Loads all TRCs from the provided folder.
func WithTRCDir(dir string) ConnectOption {
	return func(o *connectOptions) {
		o.trcDir = dir
	}
}

// Defines the local IA to use. If the provided IA is not valid,
// an error is thrown.
func WithLocalIA(ia addr.IA) ConnectOption {
	return func(o *connectOptions) {
		o.localIA = ia
	}
}

// Alternative way to choose the local IA. Not compatible with the
// WithLocalIA option.
func WithLocalIASelector(f func([]addr.IA) addr.IA) ConnectOption {
	return func(o *connectOptions) {
		o.localIASelector = f
	}
}

// If provided, the underlying http client will provide this certificate for mTLS
// if requested by the server.
func WithClientCert(certs []*x509.Certificate, privKey crypto.PrivateKey) ConnectOption {
	return func(o *connectOptions) {
		var chain [][]byte
		for _, c := range certs {
			chain = append(chain, c.Raw)
		}
		o.tlsCertificate = &tls.Certificate{
			Certificate: chain,
			PrivateKey:  privKey,
		}
	}
}

func WithToken(jwt string) ConnectOption {
	return func(o *connectOptions) {
		o.token = jwt
	}
}

// NewConnector initializes the endhost API connector using the provided api URL.
// When no TRCs are provided, the connector will try to fetch the local ISD TRC from the
// endhost API. However, since the client does not have the trust material to verify the connection
// to the endhost-api server, a man-in-the-middle attacks could theoretically happen.
func NewConnector(ctx context.Context, api string, opts ...ConnectOption) (*Connector, error) {
	options := &connectOptions{}
	for _, opt := range opts {
		opt(options)
	}
	u, err := url.Parse(api)
	if err != nil {
		return nil, err
	}
	endhostApiAddr, err := net.ResolveTCPAddr("tcp", u.Host)
	if err != nil {
		return nil, err
	}
	c := &Connector{
		api:   api,
		token: options.token,
	}
	if u.Scheme == "http" {
		options.insecure = true
	}
	clientCerts := make([]tls.Certificate, 0, 1)
	if options.tlsCertificate != nil {
		clientCerts = append(clientCerts, *options.tlsCertificate)
	}

	c.trustDB = db.NewTrustMemoryDB()

	if options.insecure {
		log.Debug("setting up endhost-api client in insecure mode")
		// accept any TLS certificate or non-tls connection
		c.httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					Certificates:       clientCerts,
				},
			},
		}
		c.UnderlayService = c.NewUnderlayService()
		c.Topology, err = c.loadTopology(ctx, options.localIA, options.localIASelector)
		if err != nil {
			return nil, err
		}
		c.TrustService = c.NewTrustService()
		c.PathService = c.NewPathService()
		c.DRKeyService = c.NewDRKeyService()
		return c, nil
	}
	localIA := options.localIA
	if options.trcDir != "" {
		log.Debug("setting up endhost-api client using stored TRCs")
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
		log.Debug("setting up endhost-api client by fetching TRC from endhost API server")
		c.httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					Certificates:       clientCerts,
				},
			},
		}
		c.UnderlayService = c.NewUnderlayService()
		c.Topology, err = c.loadTopology(ctx, options.localIA, options.localIASelector)
		if err != nil {
			return nil, err
		}
		localIA = c.Topology.LocalIA
		c.TrustService = c.NewTrustService()
		_, err := c.TrustService.TRC(ctx, uint32(localIA.ISD()), 0, 0)
		if err != nil {
			return nil, err
		}
		c.DRKeyService = c.NewDRKeyService()
	}
	// Now we should have a TRC for the local ISD in the trust store and can
	// initialize the connector properly.
	tlsVerifier := trust.NewTLSCryptoVerifier(c.trustDB)

	if localIA.IsZero() {
		// since localIA is not specified, we have to query for underlays without being able to
		// use tlsVerifier.VerifyConnection since this would require setting ServerName
		c.httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify:    true,
					VerifyPeerCertificate: tlsVerifier.VerifyServerCertificate,
					Certificates:          clientCerts,
				},
			},
		}
		c.UnderlayService = c.NewUnderlayService()
		c.Topology, err = c.loadTopology(ctx, options.localIA, options.localIASelector)
		if err != nil {
			return nil, err
		}
		// now we know the local IA, so we can modify the tls configuration
		c.httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify:    true,
					VerifyConnection:      tlsVerifier.VerifyConnection,
					VerifyPeerCertificate: tlsVerifier.VerifyServerCertificate,
					Certificates:          clientCerts,
					ServerName: fmt.Sprintf("%s,%s", c.Topology.LocalIA,
						endhostApiAddr.IP.String()),
				},
			},
		}
	} else {
		c.httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify:    true,
					VerifyConnection:      tlsVerifier.VerifyConnection,
					VerifyPeerCertificate: tlsVerifier.VerifyServerCertificate,
					Certificates:          clientCerts,
					ServerName: fmt.Sprintf("%s,%s", c.Topology.LocalIA,
						endhostApiAddr.IP.String()),
				},
			},
		}
		c.UnderlayService = c.NewUnderlayService()
		c.Topology, err = c.loadTopology(ctx, options.localIA, options.localIASelector)
		if err != nil {
			return nil, err
		}
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
	token      string
}

// loadTopology is called from NewConnector and uses the underlay service to determine the
// available underlays, the local IA and its interfaces and populates a snet.Topology struct.
func (c *Connector) loadTopology(ctx context.Context, localIA addr.IA,
	iaSelector func([]addr.IA) addr.IA) (snet.Topology, error) {

	topo := snet.Topology{}
	allUnderlays, err := c.UnderlayService.ListUnderlays(ctx, nil)
	if err != nil {
		return topo, err
	}
	c.underlays = allUnderlays
	// TODO: add support for snap
	/*if c.underlays.Udp == nil || len(c.underlays.Udp.Routers) == 0 {
		return topo, serrors.New("Local IA cannot be determined without a UDP underlay present")
	}*/

	allPossibleLocalIAs := make([]addr.IA, 0, 1)
	iaPortRange := make(map[addr.IA]snet.TopologyPortRange)
	snapIAs := make(map[addr.IA]string)
	if c.underlays.Udp != nil {
		for _, router := range c.underlays.Udp.Routers {
			ia := addr.IA(router.IsdAs)
			_, found := iaPortRange[ia]
			if !found {
				allPossibleLocalIAs = append(allPossibleLocalIAs, ia)
				iaPortRange[ia] = snet.TopologyPortRange{
					Start: uint16(router.DispatchedPortStart),
					End:   uint16(router.DispatchedPortEnd),
				}
			}
		}
	}
	if c.underlays.Snap != nil {
		for _, snap := range c.underlays.Snap.Snaps {
			snapControl := snap.Address
			for _, ia := range snap.IsdASes {
				if !slices.Contains(allPossibleLocalIAs, ia) {
					allPossibleLocalIAs = append(allPossibleLocalIAs, ia)
					snapIAs[ia] = snapControl
				}
			}
		}
	}
	if len(allPossibleLocalIAs) == 0 {
		return topo, serrors.New("No AS found")
	}
	if localIA.IsZero() {
		if iaSelector != nil {
			localIA = iaSelector(allPossibleLocalIAs)
		} else {
			localIA = allPossibleLocalIAs[0]
		}
	}
	portRange, found := iaPortRange[localIA]
	if found {
		topo.PortRange = snet.TopologyPortRange{
			Start: portRange.Start,
			End:   portRange.End,
		}
	}
	topo.LocalIA = localIA

	c.interfaces = make(map[uint16]netip.AddrPort)
	if c.underlays.Udp != nil {
		for _, router := range c.underlays.Udp.Routers {
			if localIA != addr.IA(router.IsdAs) {
				// skip routers that do not belong to selected local IA
				continue
			}
			addr, err := netip.ParseAddrPort(router.Address)
			if err != nil {
				return topo, err
			}
			for _, inf := range router.Interfaces {
				c.interfaces[uint16(inf)] = addr
			}
		}
	}
	topo.Interface = func(u uint16) (netip.AddrPort, bool) {
		addr, ok := c.interfaces[u]
		return addr, ok
	}
	if snapControl, found := snapIAs[localIA]; found {
		topo.SnapApi = snapControl
	}
	return topo, nil
}

func authInterceptor(jwtToken string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if jwtToken != "" {
				req.Header().Set("Authorization", "Bearer "+jwtToken)
			}
			return next(ctx, req)
		}
	}
}
