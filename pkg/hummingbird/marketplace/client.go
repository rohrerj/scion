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
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/trust"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type MarketplaceClient struct {
	token  string
	topo   snet.Topology
	client hummingbirdconnect.MarketplaceServiceClient
}

func (c *MarketplaceClient) withSCION(ctx context.Context, querier snet.PathQuerier, remote *snet.UDPAddr, serverName string, insecure bool) (
	hummingbirdconnect.MarketplaceServiceClient, error) {

	trustDB, err := storage.NewInMemoryTrustStorage()
	if err != nil {
		return nil, err
	}
	var localPublic *net.UDPAddr
	var dp snet.DataplanePath
	var nextHop *net.UDPAddr

	if remote.IA == c.topo.LocalIA {
		// marketplace is inside local AS
		dp = path.Empty{}
		nextHop = remote.Host
	} else {
		paths, err := querier.Query(ctx, remote.IA)
		if err != nil {
			return nil, err
		}
		if len(paths) == 0 {
			return nil, serrors.New("no paths found to marketplace")
		}
		dp = paths[0].Dataplane()
		nextHop = paths[0].UnderlayNextHop()
	}
	remote.Path = dp
	remote.NextHop = nextHop

	if remote.NextHop.IP.To4() != nil {
		localPublic = &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 0,
		}
	} else {
		localPublic = &net.UDPAddr{
			IP:   net.IPv6loopback,
			Port: 0,
		}
	}

	nc := appnet.NetworkConfig{
		Topology: c.topo,
		IA:       c.topo.LocalIA,
		QUIC: appnet.QUIC{
			TLSVerifier: trust.NewTLSCryptoVerifier(trustDB),
		},
		MTU:    1400,
		Public: localPublic,
	}
	quicStack, err := nc.QUICStack(ctx)
	if err != nil {
		return nil, err
	}
	var dialerFunc func(a net.Addr, opts ...squic.EarlyDialerOption) squic.EarlyDialer
	if insecure {
		dialerFunc = (&squic.EarlyDialerFactory{
			Transport: quicStack.Dialer.Transport,
			TLSConfig: &tls.Config{
				NextProtos:         []string{"h3", "SCION"},
				InsecureSkipVerify: true,
			},
			Rewriter: &appnet.AddressRewriter{
				Router: &snet.BaseRouter{
					Querier: querier,
				},
			},
		}).NewDialer
	} else {
		dialerFunc = (&squic.EarlyDialerFactory{
			Transport: quicStack.Dialer.Transport,
			TLSConfig: &tls.Config{
				NextProtos: []string{"h3", "SCION"},
				ServerName: serverName,
			},
			Rewriter: &appnet.AddressRewriter{
				Router: &snet.BaseRouter{
					Querier: querier,
				},
			},
		}).NewDialer
	}

	dialer := dialerFunc(remote)
	marketplaceClient := hummingbirdconnect.NewMarketplaceServiceClient(
		libconnect.HTTPClient{
			RoundTripper: &http3.Transport{
				Dial: dialer.DialEarly,
			},
		}, libconnect.BaseUrl(remote), connect.WithInterceptors(authInterceptor(c.token)))
	return marketplaceClient, nil
}

func authInterceptor(jwtToken string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("Authorization", "Bearer "+jwtToken)
			return next(ctx, req)
		}
	}
}

func parseAddr(s string) (addr.Addr, uint16, string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return addr.Addr{}, 0, "", serrors.Wrap("invalid address: split host:port", err, "addr", s)
	}
	splits := strings.Split(host, ",")
	if len(splits) != 2 {
		return addr.Addr{}, 0, "", serrors.Wrap("invalid address: split host:port", err, "addr", s)
	}
	_, err = netip.ParseAddr(splits[1])
	if err != nil {
		ipAddr, err := net.ResolveIPAddr("ip", splits[1])
		if err != nil {
			return addr.Addr{}, 0, "", serrors.Wrap("invalid address: split host:port", err, "addr", s)
		}
		s = fmt.Sprintf("[%s,%s]:%s", splits[0], ipAddr.String(), port)
	}
	a, p, err := addr.ParseAddrPort(s)
	return a, p, splits[1], err
}

// Creates a new marketplace client.
// Valid URL forms:
// https://127.0.0.1:8888
// https://my-marketplace.local:8888
// [1-ff00:0:111,127.0.0.1]:9888
// [1-ff00:0:111,my-marketplace.local]:9888
// If a SCION url is provided, the client will connect over the SCION network, otherwise over the public internet.
// If a dns name is provided, dns resolution will be done using local dns resolver.
// If insecure = true, server certificate validation will be disabled.
// path querier and local topology is only required for scion connections
func NewMarketplaceClient(ctx context.Context, url string, token string, querier snet.PathQuerier, topo snet.Topology, insecure bool) (*MarketplaceClient, error) {
	urlSplit := strings.Split(url, "://")
	api := ""
	if len(urlSplit) == 1 {
		api = urlSplit[0]
	} else if len(urlSplit) == 2 {
		api = urlSplit[1]
	} else {
		return nil, serrors.New("invalid url", "url", url)
	}
	c := &MarketplaceClient{
		token: token,
		topo:  topo,
	}
	scionAddr, port, serverName, err := parseAddr(api)
	if err == nil {
		remote := &snet.UDPAddr{
			IA:   scionAddr.IA,
			Host: net.UDPAddrFromAddrPort(netip.AddrPortFrom(scionAddr.Host.IP(), port)),
		}
		c.client, err = c.withSCION(ctx, querier, remote, serverName, insecure)
		if err != nil {
			return nil, err
		}
	} else {
		if insecure {
			c.client = hummingbirdconnect.NewMarketplaceServiceClient(&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}, url, connect.WithInterceptors(authInterceptor(token)))
		} else {
			c.client = hummingbirdconnect.NewMarketplaceServiceClient(http.DefaultClient,
				url, connect.WithInterceptors(authInterceptor(token)))
		}
	}
	return c, nil
}

type BuyMode int

const (
	FailOnError BuyMode = iota
	ContinueOnError
)

type InterfacePair struct {
	IA      uint64
	Ingress uint32
	Egress  uint32
}

func (c *MarketplaceClient) findExistingReservations(ctx context.Context, pairs []InterfacePair, bwInKbps uint32, startsAt time.Time, stopsAt time.Time) ([]*snetpath.Hop, error) {
	res, err := c.client.FetchReservations(ctx, &connect.Request[hummingbird.FetchReservationsRequest]{
		Msg: &hummingbird.FetchReservationsRequest{
			Bandwidth: &bwInKbps,
			StartsAt:  timestamppb.New(startsAt),
			StopsAt:   timestamppb.New(stopsAt),
		},
	})
	if err != nil {
		return nil, err
	}
	fmt.Println("YYY", res.Msg.Reservations)
	ret := make([]*snetpath.Hop, len(pairs))
	for i, pair := range pairs {
		for _, r := range res.Msg.Reservations {
			if r.Ia == pair.IA && r.IngressId == pair.Ingress && r.EgressId == pair.Egress {
				fmt.Println("AAA")
				ret[i] = &snetpath.Hop{
					BaseHop: snetpath.BaseHop{
						IA:      addr.IA(r.Ia),
						Ingress: uint16(r.IngressId),
						Egress:  uint16(r.EgressId),
					},
					Flyover: &snetpath.FlyoverData{
						ResID:     r.ReservationId,
						Ak:        [16]byte(r.AuthenticationKey),
						Bw:        uint16(r.Bandwidth),
						StartTime: uint32(r.StartsAt.Seconds),
						Duration:  uint16(r.StopsAt.Seconds - r.StartsAt.Seconds),
					},
				}
				break
			}
		}
	}
	return ret, nil
}

func filter[T any](s []*T, keep func(*T) bool) []*T {
	result := make([]*T, 0, len(s))
	for _, v := range s {
		if keep(v) {
			result = append(result, v)
		}
	}
	return result
}

func (c *MarketplaceClient) checkoutAssetForInterfacePair(ctx context.Context, pair InterfacePair, bwInKbps uint32, startsAt time.Time, stopsAt time.Time) ([]*hummingbird.BuyAsset, error) {
	ingressAssetsResponse, err := c.client.SearchAssets(ctx, &connect.Request[hummingbird.SearchAssetsRequest]{
		Msg: &hummingbird.SearchAssetsRequest{
			Owned:           false,
			Ia:              &pair.IA,
			IfIdIngress:     &pair.Ingress,
			MinRequiredBw:   &bwInKbps,
			StartsAtLatest:  timestamppb.New(startsAt),
			StopsAtEarliest: timestamppb.New(stopsAt),
		},
	})
	if err != nil {
		return nil, err
	}
	egressAssetsResponse, err := c.client.SearchAssets(ctx, &connect.Request[hummingbird.SearchAssetsRequest]{
		Msg: &hummingbird.SearchAssetsRequest{
			Owned:           false,
			Ia:              &pair.IA,
			IfIdEgress:      &pair.Egress,
			MinRequiredBw:   &bwInKbps,
			StartsAtLatest:  timestamppb.New(startsAt),
			StopsAtEarliest: timestamppb.New(stopsAt),
		},
	})
	if err != nil {
		return nil, err
	}
	pairAssetsResponse, err := c.client.SearchAssets(ctx, &connect.Request[hummingbird.SearchAssetsRequest]{
		Msg: &hummingbird.SearchAssetsRequest{
			Owned:           false,
			Ia:              &pair.IA,
			IfIdIngress:     &pair.Ingress,
			IfIdEgress:      &pair.Egress,
			MinRequiredBw:   &bwInKbps,
			StartsAtLatest:  timestamppb.New(startsAt),
			StopsAtEarliest: timestamppb.New(stopsAt),
		},
	})
	if err != nil {
		return nil, err
	}
	duration := uint32(stopsAt.Sub(startsAt).Seconds())
	actualPrice := func(a *hummingbird.SearchAsset) uint32 {
		granularityAdjustedDuration := duration + (a.TimeGranularity-(duration%a.TimeGranularity))%a.TimeGranularity
		return a.Price * max(a.BandwidthMin, bwInKbps) * max(a.TimeMinDuration, duration, granularityAdjustedDuration)
	}
	filterAssets := func(assets []*hummingbird.SearchAsset) []*hummingbird.SearchAsset {
		return filter(assets, func(a *hummingbird.SearchAsset) bool {
			if duration < a.TimeMinDuration {
				if a.StopsAt.Seconds <= startsAt.Unix()+int64(a.TimeMinDuration) {
					// asset is not valid because when extending duration to the minimum duration, the stops at lies outside validity period
					return false
				}
			}
			remainder := duration % a.TimeGranularity
			if remainder != 0 {
				addedDuration := a.TimeGranularity - remainder
				if a.StopsAt.Seconds <= startsAt.Unix()+int64(addedDuration) {
					// asset is not valid because when extending duration to a multiple of time granularity, the stops at lies outside validity period
					return false
				}
			}
			if a.BandwidthMin > bwInKbps {
				if a.Bandwidth < a.BandwidthMin {
					// there is not enough bandwidth to satisfy bandwidth min
					return false
				}
			}
			return true
		})
	}
	sortAssets := func(assets []*hummingbird.SearchAsset) []*hummingbird.SearchAsset {
		sort.Slice(assets, func(i, j int) bool {
			return actualPrice(assets[i]) < actualPrice(assets[j])
		})
		return assets
	}
	buildBuyRequest := func(a *hummingbird.SearchAsset) *hummingbird.BuyAsset {
		addedDuration := uint32(0)
		if duration < a.TimeMinDuration {
			addedDuration = a.TimeMinDuration - duration
		}
		remainder := duration % a.TimeGranularity
		if remainder != 0 {
			addedDuration = a.TimeGranularity - remainder
		}
		return &hummingbird.BuyAsset{
			AssetId:         a.AssetId,
			BandwidthExact:  max(bwInKbps, a.BandwidthMin),
			StartsAtExactly: timestamppb.New(startsAt),
			StopsAtExactly:  timestamppb.New(stopsAt.Add(time.Duration(addedDuration) * time.Second)),
		}
	}
	ingressAssets := sortAssets(filterAssets(ingressAssetsResponse.Msg.Assets))
	egressAssets := sortAssets(filterAssets(egressAssetsResponse.Msg.Assets))
	pairAssets := sortAssets(filterAssets(pairAssetsResponse.Msg.Assets))

	order := []*hummingbird.BuyAsset{}
	if len(pairAssets) != 0 {
		if len(ingressAssets) != 0 && len(egressAssets) != 0 {
			if actualPrice(pairAssets[0]) <= actualPrice(ingressAssets[0])+actualPrice(egressAssets[0]) {
				order = append(order, buildBuyRequest(pairAssets[0]))
			} else {
				order = append(order, buildBuyRequest(ingressAssets[0]), buildBuyRequest(egressAssets[0]))
			}
		} else {
			order = append(order, buildBuyRequest(pairAssets[0]))
		}
	} else if len(ingressAssets) != 0 && len(egressAssets) != 0 {
		order = append(order, buildBuyRequest(ingressAssets[0]), buildBuyRequest(egressAssets[0]))
	} else {
		log.Debug("no assets found", "ia", addr.IA(pair.IA).String(), "ingress", pair.Ingress, "egress", pair.Egress, "startsat", startsAt, "stopsat", stopsAt)
		return nil, serrors.New("no assets found", "ia", addr.IA(pair.IA).String(), "ingress", pair.Ingress, "egress", pair.Egress, "startsat", startsAt, "stopsat", stopsAt)
	}
	return order, nil
}

type assetInfo struct {
	id       string
	startsAt time.Time
	stopsAt  time.Time
}

func (c *MarketplaceClient) ObtainReservationsForInterfacePairs(ctx context.Context, pairs []InterfacePair, bwInKbps uint32, startsAt time.Time, stopsAt time.Time,
	maxPrice uint64, buyMode BuyMode, fetchReservations bool, num_retries int) ([]*snetpath.Hop, error) {
	startsAt = startsAt.Truncate(time.Second)
	stopsAt = stopsAt.Truncate(time.Second)
	hops := make([]*snetpath.Hop, len(pairs))
	var err error
	if fetchReservations {
		hops, err = c.findExistingReservations(ctx, pairs, bwInKbps, startsAt, stopsAt)
		if err != nil {
			return nil, err
		}
	}
	var orders = []*hummingbird.BuyAsset{}
	fmt.Println("XXX", hops)
	iaAssets := map[uint64][]assetInfo{}
	var boughtAssets *connect.Response[hummingbird.BuyAssetsResponse]
	success := false
	for retry := -1; retry < num_retries; retry++ {
		orders = []*hummingbird.BuyAsset{}
		for i, pair := range pairs {
			if hops[i] != nil {
				continue
			}
			o, err := c.checkoutAssetForInterfacePair(ctx, pair, bwInKbps, startsAt, stopsAt)
			if err != nil {
				if buyMode == FailOnError {
					return nil, err
				} else if buyMode == ContinueOnError {
					continue
				}
			}
			orders = append(orders, o...)
		}
		log.FromCtx(ctx).Debug("Purchase", "assets", orders)
		boughtAssets, err = c.client.BuyAssets(ctx, &connect.Request[hummingbird.BuyAssetsRequest]{
			Msg: &hummingbird.BuyAssetsRequest{
				Assets:   orders,
				MaxPrice: maxPrice,
			},
		})
		if err != nil {
			log.FromCtx(ctx).Debug("Error buying asset", "err", err)
			continue
		}
		break
	}
	if !success {
		return nil, err
	}
	foundAssets, err := c.client.SearchAssets(ctx, &connect.Request[hummingbird.SearchAssetsRequest]{
		Msg: &hummingbird.SearchAssetsRequest{
			Owned:           true,
			MinRequiredBw:   &bwInKbps,
			StartsAtLatest:  timestamppb.New(startsAt),
			StopsAtEarliest: timestamppb.New(stopsAt),
		},
	})
	if err != nil {
		return nil, err
	}
	for _, boughtAsset := range boughtAssets.Msg.Assets {
		for _, foundAsset := range foundAssets.Msg.Assets {
			if boughtAsset.AssetId == foundAsset.AssetId {
				current, found := iaAssets[foundAsset.Ia]
				if found {
					iaAssets[foundAsset.Ia] = append(current, assetInfo{id: foundAsset.AssetId, stopsAt: foundAsset.StopsAt.AsTime(), startsAt: foundAsset.StartsAt.AsTime()})
				} else {
					iaAssets[foundAsset.Ia] = []assetInfo{{id: foundAsset.AssetId, stopsAt: foundAsset.StopsAt.AsTime(), startsAt: foundAsset.StartsAt.AsTime()}}
				}
				break
			}
		}
	}

	if !success {
		return nil, err
	}
	redeemedHops, err := c.redeemHopsConcurrently(ctx, pairs, iaAssets, startsAt, stopsAt)
	if err != nil {
		return nil, err
	}
	for i, hop := range hops {
		if hop != nil {
			redeemedHops[i] = hops[i]
		}
	}
	return redeemedHops, nil
}

func later(a time.Time, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}
func earlier(a time.Time, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (c *MarketplaceClient) redeemHopsConcurrently(ctx context.Context, pairs []InterfacePair, iaAssets map[uint64][]assetInfo, startsAt time.Time, stopsAt time.Time) ([]*snetpath.Hop, error) {
	type requestInfo struct {
		request  *hummingbird.RedeemAssetRequest
		startsAt time.Time
		stopsAt  time.Time
	}
	requests := make([]*requestInfo, len(pairs))
	responses := make([]*hummingbird.RedeemAssetResponse, len(pairs))
	errors := make([]error, len(pairs))
	for i, pair := range pairs {
		assets, found := iaAssets[pair.IA]
		if !found || len(assets) == 0 {
			continue
		}
		if len(assets) == 1 {
			requests[i] = &requestInfo{
				request: &hummingbird.RedeemAssetRequest{
					Interfaces: &hummingbird.RedeemAssetRequest_IfPairAssetId{
						IfPairAssetId: assets[0].id,
					},
				},
				startsAt: assets[0].startsAt,
				stopsAt:  assets[0].stopsAt,
			}
		} else if len(assets) == 2 {
			requests[i] = &requestInfo{
				request: &hummingbird.RedeemAssetRequest{
					Interfaces: &hummingbird.RedeemAssetRequest_Pair{
						Pair: &hummingbird.IngressEgressPair{
							IngressAssetId: assets[0].id,
							EgressAssetId:  assets[1].id,
						},
					},
				},
				startsAt: later(assets[0].startsAt, assets[1].startsAt),
				stopsAt:  earlier(assets[0].stopsAt, assets[1].stopsAt),
			}
		}
	}
	wg := sync.WaitGroup{}
	wg.Add(len(pairs))
	for i := range pairs {
		go func(i int) {
			defer wg.Done()
			if requests[i] == nil {
				return
			}
			rep, err := c.client.RedeemAsset(ctx, &connect.Request[hummingbird.RedeemAssetRequest]{
				Msg: requests[i].request,
			})
			if err != nil {
				errors[i] = err
				return
			}
			responses[i] = rep.Msg
		}(i)
	}
	wg.Wait()
	ret := make([]*snetpath.Hop, len(pairs))
	for i := 0; i < len(pairs); i++ {
		if responses[i] != nil {
			ret[i] = &snetpath.Hop{
				BaseHop: snetpath.BaseHop{
					IA:      addr.IA(pairs[i].IA),
					Ingress: uint16(pairs[i].Ingress),
					Egress:  uint16(pairs[i].Egress),
				},
				Flyover: &snetpath.FlyoverData{
					ResID:     responses[i].ReservationId,
					Ak:        [16]byte(responses[i].AuthenticationKey),
					Bw:        uint16(responses[i].BwDataplaneEncoding),
					StartTime: uint32(requests[i].startsAt.Unix()),
					Duration:  uint16(requests[i].stopsAt.Sub(requests[i].startsAt) / time.Second),
				},
			}
		} else if errors[i] != nil {
			log.FromCtx(ctx).Debug("error redeeming asset", "err", errors[i])
			ret[i] = &snetpath.Hop{
				BaseHop: snetpath.BaseHop{
					IA:      addr.IA(pairs[i].IA),
					Ingress: uint16(pairs[i].Ingress),
					Egress:  uint16(pairs[i].Egress),
				},
			}
		} else {
			ret[i] = &snetpath.Hop{
				BaseHop: snetpath.BaseHop{
					IA:      addr.IA(pairs[i].IA),
					Ingress: uint16(pairs[i].Ingress),
					Egress:  uint16(pairs[i].Egress),
				},
			}
		}
	}
	return ret, nil
}

// ObtainReservationsFullPath tries to obtain reservations for the full path provided.
// buyMode defines whether it should try to continue searching and buying assets in other ASes if purchase of an asset for one AS fails (e.g. because no asset matching the filters exists)
// fetchReservations enables fetching already owned reservations. If reservations that match IA, ingress, egress, bwInKbps, startsAt and stopsAt are found, those are used instead of buying new ones.
// It could happen that an asset gets bought by some other user between searching and buying the asset ourselves. With num_retries we can repeat the search and buy step if this happens.
func (c *MarketplaceClient) ObtainReservationsFullPath(ctx context.Context, path snet.Path, bwInKbps uint32, startsAt time.Time, stopsAt time.Time,
	maxPrice uint64, buyMode BuyMode, fetchReservations bool, num_retries int) ([]*snetpath.Hop, error) {

	pairs := []InterfacePair{}
	ifaces := path.Metadata().Interfaces
	pairs = append(pairs, InterfacePair{
		IA:      uint64(ifaces[0].IA),
		Ingress: uint32(0),
		Egress:  uint32(ifaces[0].ID),
	})
	i := 1
	for ; i < len(ifaces)-1; i += 2 {
		pairs = append(pairs, InterfacePair{
			IA:      uint64(ifaces[i].IA),
			Ingress: uint32(ifaces[i].ID),
			Egress:  uint32(ifaces[i+1].ID),
		})
	}
	for ; i < len(ifaces); i++ {
		pairs = append(pairs, InterfacePair{
			IA:      uint64(ifaces[i].IA),
			Ingress: uint32(ifaces[i].ID),
			Egress:  0,
		})
	}
	return c.ObtainReservationsForInterfacePairs(ctx, pairs, bwInKbps, startsAt, stopsAt, maxPrice, buyMode, fetchReservations, num_retries)
}
