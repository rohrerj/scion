// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package marketplace

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/app/appnet"
)

// ClientOptions configures the transport used by NewClientSet.
// Querier and Topology are required only for SCION connections.
type ClientOptions struct {
	Querier  snet.PathQuerier
	Topology snet.Topology
	Insecure bool
}

// ClientSet contains all marketplace API clients backed by one shared transport.
// Close releases that transport, and must be called once the set is no longer used.
type ClientSet struct {
	Marketplace hummingbirdconnect.MarketplaceServiceClient
	Redemption  hummingbirdconnect.RedemptionServiceClient
	Account     hummingbirdconnect.AccountServiceClient
	Authority   string
	SCION       bool

	// scion is the transport to a marketplace reached over SCION, nil for one reached over TCP.
	scion *scionTransport
}

// scionTransport are the layers a SCION marketplace connection is built from, outermost first.
// They are kept together because closing them is only correct in this order, see close.
type scionTransport struct {
	h3   *http3.Transport
	quic *quic.Transport
	conn *snet.Conn
}

// close tears the layers down from the outside in.
// http3 closes the HTTP/3 connections gracefully, so the marketplace learns of the shutdown;
// otherwise it holds its side of every connection until the idle timeout expires.
// Then QUIC is stopped. And finally the SCION socket is closed.
func (t *scionTransport) close() error {
	var errs []error
	if err := t.h3.Close(); err != nil {
		errs = append(errs, serrors.Wrap("closing the HTTP/3 transport", err))
	}
	if err := t.quic.Close(); err != nil {
		errs = append(errs, serrors.Wrap("closing the QUIC transport", err))
	}
	if err := t.conn.Close(); err != nil {
		errs = append(errs, serrors.Wrap("closing the SCION connection", err))
	}
	return errors.Join(errs...)
}

// IsSCIONURL reports whether rawURL contains a SCION address.
func IsSCIONURL(rawURL string) bool {
	api, err := endpointAddress(rawURL)
	if err != nil {
		return false
	}
	return isSCIONAddress(api)
}

// Close releases the transport shared by the clients of the set,
// which must not be used afterwards. Calling it more than once is a no-op.
func (s *ClientSet) Close() error {
	if s.scion == nil {
		return nil
	}
	transport := s.scion
	s.scion = nil
	return transport.close()
}

// NewClientSet creates marketplace, redemption, and account clients that share
// the same TCP or SCION transport.
//
// Valid URL forms include:
//
//	https://127.0.0.1:31888
//	https://my-marketplace.local:31888
//	[1-ff00:0:111,127.0.0.1]:31888
//	[1-ff00:0:111,my-marketplace.local]:31888
func NewClientSet(
	ctx context.Context,
	rawURL string,
	token string,
	options ClientOptions,
) (*ClientSet, error) {
	api, err := endpointAddress(rawURL)
	if err != nil {
		return nil, err
	}
	interceptor := connect.WithInterceptors(NewAuthInterceptor(token))
	if !isSCIONAddress(api) {
		httpClient := http.DefaultClient
		if options.Insecure {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			httpClient = &http.Client{Transport: transport}
		}
		return newClientSet(httpClient, rawURL, api, false, interceptor), nil
	}
	scionAddr, port, serverName, err := parseSCIONAddress(api)
	if err != nil {
		return nil, err
	}
	if options.Querier == nil {
		return nil, serrors.New("SCION marketplace connection requires a path querier")
	}
	if options.Topology.LocalIA.IsZero() {
		return nil, serrors.New("SCION marketplace connection requires a local topology")
	}
	remote := &snet.UDPAddr{
		IA:   scionAddr.IA,
		Host: net.UDPAddrFromAddrPort(netip.AddrPortFrom(scionAddr.Host.IP(), port)),
	}
	httpClient, transport, baseURL, err := newSCIONHTTPClient(ctx, remote, serverName, options)
	if err != nil {
		return nil, err
	}
	authority := strings.TrimPrefix(baseURL, "https://")
	set := newClientSet(httpClient, baseURL, authority, true, interceptor)
	set.scion = transport
	return set, nil
}

func newClientSet(
	httpClient connect.HTTPClient,
	baseURL string,
	authority string,
	scion bool,
	options ...connect.ClientOption,
) *ClientSet {
	return &ClientSet{
		Marketplace: hummingbirdconnect.NewMarketplaceServiceClient(
			httpClient, baseURL, options...),
		Redemption: hummingbirdconnect.NewRedemptionServiceClient(
			httpClient, baseURL, options...),
		Account: hummingbirdconnect.NewAccountServiceClient(
			httpClient, baseURL, options...),
		Authority: authority,
		SCION:     scion,
	}
}

func newSCIONHTTPClient(
	ctx context.Context,
	remote *snet.UDPAddr,
	serverName string,
	options ClientOptions,
) (connect.HTTPClient, *scionTransport, string, error) {
	if remote.IA == options.Topology.LocalIA {
		remote.Path = snetpath.Empty{}
		remote.NextHop = remote.Host
	} else {
		paths, err := options.Querier.Query(ctx, remote.IA)
		if err != nil {
			return nil, nil, "", err
		}
		if len(paths) == 0 {
			return nil, nil, "", serrors.New("no paths found to marketplace")
		}
		remote.Path = paths[0].Dataplane()
		remote.NextHop = paths[0].UnderlayNextHop()
	}
	conn, err := net.Dial("udp", remote.NextHop.String())
	if err != nil {
		return nil, nil, "", err
	}
	localPublic, ok := conn.LocalAddr().(*net.UDPAddr)
	if closeErr := conn.Close(); closeErr != nil {
		return nil, nil, "", closeErr
	}
	if !ok {
		return nil, nil, "", serrors.New("localAddr not UDP addr")
	}
	sn := snet.SCIONNetwork{
		Topology:    options.Topology,
		SCMPHandler: snet.DefaultSCMPHandler{},
	}
	localAddr := &net.UDPAddr{
		IP:   localPublic.IP,
		Port: 0,
		Zone: localPublic.Zone,
	}
	client, err := sn.Listen(ctx, "udp", localAddr)
	if err != nil {
		return nil, nil, "", err
	}
	clientTransport := &quic.Transport{
		Conn: client,
	}
	dialerFunc := (&squic.EarlyDialerFactory{
		Transport: clientTransport,
		TLSConfig: &tls.Config{
			NextProtos:         []string{"h3", "SCION"},
			ServerName:         serverName,
			InsecureSkipVerify: options.Insecure,
		},
		Rewriter: &appnet.AddressRewriter{
			Router: &snet.BaseRouter{
				Querier: options.Querier,
			},
		},
		QUICConfig: &quic.Config{
			InitialPacketSize: 1200,
		},
	}).NewDialer
	dialer := dialerFunc(remote)
	roundTripper := &http3.Transport{Dial: dialer.DialEarly}
	transport := &scionTransport{
		h3:   roundTripper,
		quic: clientTransport,
		conn: client,
	}
	return libconnect.HTTPClient{RoundTripper: roundTripper}, transport,
		libconnect.BaseUrl(remote), nil
}

type AuthInterceptor struct {
	token string
}

func NewAuthInterceptor(token string) *AuthInterceptor {
	return &AuthInterceptor{token: token}
}

func (a *AuthInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("Authorization", "Bearer "+a.token)
		return next(ctx, req)
	}
}

func (a *AuthInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		conn.RequestHeader().Set("Authorization", "Bearer "+a.token)
		return conn
	}
}

func (a *AuthInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

func endpointAddress(rawURL string) (string, error) {
	if strings.Count(rawURL, "://") > 1 {
		return "", serrors.New("invalid url", "url", rawURL)
	}
	if _, api, ok := strings.Cut(rawURL, "://"); ok {
		return api, nil
	}
	return rawURL, nil
}

func isSCIONAddress(s string) bool {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	ia, host, ok := strings.Cut(host, ",")
	if !ok || host == "" {
		return false
	}
	_, err = addr.ParseIA(ia)
	return err == nil
}

func parseSCIONAddress(s string) (addr.Addr, uint16, string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return addr.Addr{}, 0, "", serrors.Wrap("invalid address: split host:port", err,
			"addr", s)
	}
	splits := strings.Split(host, ",")
	if len(splits) != 2 {
		return addr.Addr{}, 0, "", serrors.New("invalid SCION address", "addr", s)
	}
	if _, err := netip.ParseAddr(splits[1]); err != nil {
		ipAddr, err := net.ResolveIPAddr("ip", splits[1])
		if err != nil {
			return addr.Addr{}, 0, "", serrors.Wrap("resolving SCION host", err, "addr", s)
		}
		s = fmt.Sprintf("[%s,%s]:%s", splits[0], ipAddr.String(), port)
	}
	a, p, err := addr.ParseAddrPort(s)
	return a, p, splits[1], err
}
