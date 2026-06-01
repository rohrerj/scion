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

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/endhost"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/trust"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func authInterceptor(jwtToken string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("Authorization", "Bearer "+jwtToken)
			return next(ctx, req)
		}
	}
}
func printOptions() {
	fmt.Println("-> info")
	fmt.Println("-> search")
	fmt.Println("-> buy")
	fmt.Println("-> split")
	fmt.Println("-> combine")
	fmt.Println("-> redeem")
	fmt.Println("-> reservation")
	fmt.Println("-> exit")
}

type Querier struct {
	Connector *endhost.Connector
}

func (q *Querier) Query(ctx context.Context, ia addr.IA) ([]snet.Path, error) {
	return q.Connector.PathService.Paths(ctx, ia, q.Connector.Topology.LocalIA)
}

func withSCION(ctx context.Context, endhostAPI string, remote *snet.UDPAddr, token string) (hummingbirdconnect.MarketplaceServiceClient, error) {
	connector, err := endhost.NewConnector(ctx, endhostAPI)
	if err != nil {
		return nil, err
	}
	trustDB, err := storage.NewInMemoryTrustStorage()
	if err != nil {
		return nil, err
	}
	var localPublic *net.UDPAddr
	var dp snet.DataplanePath
	var nextHop *net.UDPAddr

	if remote.IA == connector.Topology.LocalIA {
		// marketplace is inside local AS
		dp = path.Empty{}
		nextHop = remote.Host
	} else {
		paths, err := connector.PathService.Paths(ctx, remote.IA, connector.Topology.LocalIA)
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
		Topology: connector.Topology,
		IA:       connector.Topology.LocalIA,
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

	dialerFunc := (&squic.EarlyDialerFactory{
		Transport: quicStack.InsecureDialer.Transport,
		TLSConfig: func() *tls.Config {
			cfg := quicStack.InsecureDialer.TLSConfig.Clone()
			cfg.NextProtos = []string{"h3", "SCION"}
			return cfg
		}(),
		Rewriter: &appnet.AddressRewriter{
			Router: &snet.BaseRouter{
				Querier: &Querier{
					Connector: connector,
				},
			},
		},
	}).NewDialer

	dialer := dialerFunc(remote)
	client := hummingbirdconnect.NewMarketplaceServiceClient(
		libconnect.HTTPClient{
			RoundTripper: &http3.Transport{
				Dial: dialer.DialEarly,
			},
		}, libconnect.BaseUrl(remote), connect.WithInterceptors(authInterceptor(token)))
	return client, nil
}

func userInteraction() {
	reader := bufio.NewReader(os.Stdin)
	defaultMarketplaceAddr := "https://localhost:8888"
	url := *readOptionalString(reader, "marketplace_api: ", &defaultMarketplaceAddr)
	defaultJWT := ""
	token := *readOptionalString(reader, "jwt_token: ", &defaultJWT)
	ctx := context.Background()
	var client hummingbirdconnect.MarketplaceServiceClient
	urlSplit := strings.Split(url, "://")
	api := ""
	if len(urlSplit) == 1 {
		api = urlSplit[0]
	} else if len(urlSplit) == 2 {
		api = urlSplit[1]
	} else {
		fmt.Println("invalid url", url)
		return
	}
	scionAddr, port, err := addr.ParseAddrPort(api)
	if err == nil {
		remote := &snet.UDPAddr{
			IA:   scionAddr.IA,
			Host: net.UDPAddrFromAddrPort(netip.AddrPortFrom(scionAddr.Host.IP(), port)),
		}
		endhostApi := readOptionalString(reader, "endhostAPI: ", nil)
		if endhostApi == nil {
			fmt.Println("invalid endhost API")
			return
		}
		client, err = withSCION(ctx, *endhostApi, remote, token)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("use SCION connection")
	} else {
		client = hummingbirdconnect.NewMarketplaceServiceClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}, url, connect.WithInterceptors(authInterceptor(token)))
		fmt.Println("use TCP connection")
	}
	for {
		printOptions()
		option, err := reader.ReadString('\n')
		option = strings.TrimSpace(option)
		if err != nil {
			fmt.Println(err)
			continue
		}
		switch {
		case option == "info":
			handleInfo(ctx, client)
		case option == "search":
			handleSearch(ctx, reader, client)
		case option == "buy":
			handleBuy(ctx, reader, client)
		case option == "split":
			handleSplit(ctx, reader, client)
		case option == "combine":
			handleCombine(ctx, reader, client)
		case option == "redeem":
			handleRedeem(ctx, reader, client)
		case option == "reservation":
			handleReservation(ctx, reader, client)
		case option == "exit":
			return
		}
		fmt.Println("----------")
	}
}
func handleSplit(ctx context.Context, reader *bufio.Reader, c hummingbirdconnect.MarketplaceServiceClient) {
	fmt.Println("Handle split asset query.")
	assetID := readUint64(reader, "assetID: ")
	splitOption := readOptionalString(reader, "spit using axis [bw,time]: ", nil)
	if splitOption == nil {
		fmt.Println("invalid split option.")
		return
	}
	req := &hummingbird.SplitAssetRequest{
		AssetId: assetID,
	}
	switch *splitOption {
	case "bw":
		bwSplit := readUint64(reader, "bw split: ")
		req.SplitOption = &hummingbird.SplitAssetRequest_BwSplit{
			BwSplit: bwSplit,
		}
	case "time":
		timeSplit := readTime(reader, "time split (2006-01-02T15:04:05): ")
		req.SplitOption = &hummingbird.SplitAssetRequest_TimeSplit{
			TimeSplit: timestamppb.New(timeSplit),
		}
	default:
		fmt.Println("invalid split option.")
		return
	}
	resp, err := c.SplitAsset(ctx, &connect.Request[hummingbird.SplitAssetRequest]{
		Msg: req,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("asset split into %d and %d\n", resp.Msg.AssetId_1, resp.Msg.AssetId_2)
}
func handleCombine(ctx context.Context, reader *bufio.Reader, c hummingbirdconnect.MarketplaceServiceClient) {
	fmt.Println("Handle combine assets query.")
	asset1 := readUint64(reader, "asset 1: ")
	asset2 := readUint64(reader, "asset 2: ")
	resp, err := c.CombineAssets(ctx, &connect.Request[hummingbird.CombineAssetRequest]{
		Msg: &hummingbird.CombineAssetRequest{
			AssetId_1: asset1,
			AssetId_2: asset2,
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("assets combined into %d\n", resp.Msg.AssetId)
}
func handleReservation(ctx context.Context, reader *bufio.Reader, c hummingbirdconnect.MarketplaceServiceClient) {
	var ia *uint64
	var ingress *uint32
	var egress *uint32
	var bw *uint64
	var startsAt *time.Time
	var stopsAt *time.Time
	fmt.Println("Handle fetch reservation query. Filters are ignored if empty.")
	ia = readOptionalIAUint64(reader, "IA: ")
	ingress = readOptionalUint32(reader, "Ingress: ")
	egress = readOptionalUint32(reader, "Egress: ")
	bw = readOptionalUint64(reader, "BW: ")
	startsAt = readOptionalTime(reader, "Starts At (2006-01-02T15:04:05): ")
	stopsAt = readOptionalTime(reader, "Stops At (2006-01-02T15:04:05): ")

	req := &hummingbird.FetchReservationsRequest{
		Ia:        ia,
		IngressId: ingress,
		EgressId:  egress,
		Bw:        bw,
	}
	if startsAt != nil {
		req.StartsAt = timestamppb.New(*startsAt)
	}
	if stopsAt != nil {
		req.StopsAt = timestamppb.New(*stopsAt)
	}
	rep, err := c.FetchReservations(ctx, &connect.Request[hummingbird.FetchReservationsRequest]{
		Msg: req,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	type Reservation struct {
		ResId     uint64
		Ia        addr.IA
		IngressId uint32
		EgressId  uint32
		Bw        uint64
		StartsAt  time.Time
		StopsAt   time.Time
		Ak        string
	}
	transformed := make([]*Reservation, 0, len(rep.Msg.Reservations))
	for _, res := range rep.Msg.Reservations {
		transformed = append(transformed, &Reservation{
			ResId:     res.ResId,
			Ia:        addr.IA(res.Ia),
			IngressId: res.IngressId,
			EgressId:  res.EgressId,
			Bw:        res.Bw,
			StartsAt:  res.StartsAt.AsTime(),
			StopsAt:   res.StopsAt.AsTime(),
		})
	}
	j, err := json.MarshalIndent(transformed, "", "\t")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(j))
}

func handleRedeem(ctx context.Context, reader *bufio.Reader, c hummingbirdconnect.MarketplaceServiceClient) {
	fmt.Println("Redeem Query.")
	var err error
	option := readOptionalUint32(reader, "Select option:\n0: ingress and egress assets\n1: interface-pair asset:\n")
	var rep *connect.Response[hummingbird.RedeemAssetResponse]
	if option == nil {
		return
	} else if *option == 0 {
		ingressAssetID := readUint64(reader, "Ingress Asset ID: ")
		egressAssetID := readUint64(reader, "Egress Asset ID: ")
		b := readOptionalBool(reader, "Confirm redemption? [true,false]: ")
		if b != nil && *b == false {
			fmt.Println("cancel redemption")
			return
		}
		rep, err = c.RedeemAsset(ctx, &connect.Request[hummingbird.RedeemAssetRequest]{
			Msg: &hummingbird.RedeemAssetRequest{
				IngressAssetId: ingressAssetID,
				EgressAssetId:  egressAssetID,
			},
		})
	} else if *option == 1 {
		assetID := readUint64(reader, "Interface-pair Asset ID: ")
		b := readOptionalBool(reader, "Confirm redemption? [true,false]: ")
		if b != nil && *b == false {
			fmt.Println("cancel redemption")
			return
		}
		rep, err = c.RedeemAsset(ctx, &connect.Request[hummingbird.RedeemAssetRequest]{
			Msg: &hummingbird.RedeemAssetRequest{
				IfPairAssetId: &assetID,
			},
		})
	} else {
		return
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Redemption Result:")
	fmt.Printf("ResID: %d\nAk: %s\nBw: %d\nEncoding: %d\n", rep.Msg.ResId, rep.Msg.Ak, rep.Msg.BwRounded, rep.Msg.BwDataplaneEncoding)

}
func printBuyOptions() {
	fmt.Println("-> add")
	fmt.Println("-> remove")
	fmt.Println("-> list")
	fmt.Println("-> submit")
	fmt.Println("-> cancel")
}
func handleBuy(ctx context.Context, reader *bufio.Reader, c hummingbirdconnect.MarketplaceServiceClient) {
	fmt.Println("Buy Query.")
	buyAssets := make([]*hummingbird.BuyAsset, 0, 1)
	for {
		fmt.Printf("Currently %d assets in the shopping cart.\n", len(buyAssets))
		printBuyOptions()
		option, err := reader.ReadString('\n')
		option = strings.TrimSpace(option)
		if err != nil {
			fmt.Println(err)
			continue
		}
		switch {
		case option == "add":
			buyAsset := &hummingbird.BuyAsset{
				AssetId:         readUint64(reader, "AssetID: "),
				StartsAtExactly: timestamppb.New(readTime(reader, "Starts at exactly (2006-01-02T15:04:05): ")),
				StopsAtExactly:  timestamppb.New(readTime(reader, "Stops at exactly (2006-01-02T15:04:05): ")),
				BwExact:         readUint64(reader, "BW exact: "),
			}
			buyAssets = append(buyAssets, buyAsset)
		case option == "remove":
			index := readUint64(reader, "List index to remove: ")
			if int(index) >= len(buyAssets) {
				fmt.Println("index invalid")
				break
			}
			buyAssets = append(buyAssets[:index], buyAssets[index+1:]...)
		case option == "list":
			for index, asset := range buyAssets {
				jsonAsset, _ := json.Marshal(asset)
				fmt.Printf("%d:%s\n", index, string(jsonAsset))
			}
		case option == "submit":
			maxPrice := readUint64(reader, "Max Price: ")
			rep, err := c.BuyAssets(ctx, &connect.Request[hummingbird.BuyAssetsRequest]{
				Msg: &hummingbird.BuyAssetsRequest{
					Assets:   buyAssets,
					MaxPrice: maxPrice,
				},
			})
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Printf("Bought assets for a total cost of %d\n", rep.Msg.Cost)
			fmt.Print("[")
			for _, boughtAsset := range rep.Msg.Assets {
				fmt.Printf("%d,", boughtAsset.AssetId)
			}
			fmt.Print("]\n")
			return
		case option == "cancel":
			return
		}
	}
}

func handleSearch(ctx context.Context, reader *bufio.Reader, c hummingbirdconnect.MarketplaceServiceClient) {
	var owned *bool
	var ia *uint64
	var assetType *hummingbird.AssetType
	var ingress *uint32
	var egress *uint32
	var minReqBw *uint64
	var price *uint64
	var startsAtLatest *time.Time
	var stopsAtEarliest *time.Time
	fmt.Println("Search Query. Owned is mandatory, other filters are ignored if empty.")

	owned = readOptionalBool(reader, "Owned (true,false): ")
	ia = readOptionalIAUint64(reader, "IA: ")
	assetType = readOptionalAssetType(reader, "Asset Type (ingress,egress,pair): ")
	ingress = readOptionalUint32(reader, "Ingress: ")
	egress = readOptionalUint32(reader, "Egress: ")
	minReqBw = readOptionalUint64(reader, "Min Required BW: ")
	price = readOptionalUint64(reader, "Price: ")
	startsAtLatest = readOptionalTime(reader, "Starts At Latest (2006-01-02T15:04:05): ")
	stopsAtEarliest = readOptionalTime(reader, "Stops At Earliest (2006-01-02T15:04:05): ")
	if owned == nil {
		tmp := false
		owned = &tmp
	}
	msg := &hummingbird.SearchAssetsRequest{
		Owned:         *owned,
		Ia:            ia,
		AssetType:     assetType,
		IfIdIngress:   ingress,
		IfIdEgress:    egress,
		MinRequiredBw: minReqBw,
		Price:         price,
	}
	if startsAtLatest != nil {
		msg.StartsAtLatest = timestamppb.New(*startsAtLatest)
	}
	if stopsAtEarliest != nil {
		msg.StopsAtEarliest = timestamppb.New(*stopsAtEarliest)
	}
	rep, err := c.SearchAssets(ctx, &connect.Request[hummingbird.SearchAssetsRequest]{
		Msg: msg,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	transformed := make([]Asset, 0, len(rep.Msg.Assets))
	for _, asset := range rep.Msg.Assets {
		transformed = append(transformed, Asset{
			ID:              asset.AssetId,
			IA:              addr.IA(asset.Ia),
			Bandwidth:       asset.Bw,
			AssetType:       asset.AssetType,
			StartAt:         asset.StartsAt.AsTime(),
			StopsAt:         asset.StopsAt.AsTime(),
			Price:           asset.Price,
			IfIdIngress:     asset.IfIdIngress,
			IfIdEgress:      asset.IfIdEgress,
			TimeGranularity: asset.TimeGranularity,
		})
	}
	sort.Slice(transformed, func(i, j int) bool {
		return transformed[i].ID < transformed[j].ID
	})
	j, err := json.MarshalIndent(transformed, "", "\t")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(j))
}

func handleInfo(ctx context.Context, c hummingbirdconnect.MarketplaceServiceClient) {
	info, err := c.Info(ctx, &connect.Request[hummingbird.MarketplaceInfoRequest]{})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Version: %d.%d, Currency: %s\n", info.Msg.ApiMajorVersion, info.Msg.ApiMinorVersion, info.Msg.Currency)
}

type AssetType string

func readUint64(reader *bufio.Reader, prompt string) uint64 {
	fmt.Print(prompt)

	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)

	v, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		fmt.Println("Invalid uint64")
		return 0
	}

	return v
}

func readOptionalIAUint64(reader *bufio.Reader, prompt string) *uint64 {
	fmt.Print(prompt)

	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)

	if text == "" {
		return nil
	}
	ia, err := addr.ParseIA(text)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	v := uint64(ia)

	return &v
}

func readOptionalString(reader *bufio.Reader, prompt string, defaultStr *string) *string {
	fmt.Print(prompt)

	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)

	if text == "" {
		return defaultStr
	}

	return &text
}

func readOptionalUint64(reader *bufio.Reader, prompt string) *uint64 {
	fmt.Print(prompt)

	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)

	if text == "" {
		return nil
	}

	v, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		fmt.Println("Invalid uint64")
		return nil
	}

	return &v
}

func readOptionalUint32(reader *bufio.Reader, prompt string) *uint32 {
	fmt.Print(prompt)

	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)

	if text == "" {
		return nil
	}

	v64, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		fmt.Println("Invalid uint32")
		return nil
	}

	v := uint32(v64)
	return &v
}

func readOptionalBool(reader *bufio.Reader, prompt string) *bool {
	fmt.Print(prompt)

	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)

	if text == "" {
		return nil
	}

	v, err := strconv.ParseBool(text)
	if err != nil {
		fmt.Println("Invalid bool")
		return nil
	}

	return &v
}

func readTime(reader *bufio.Reader, prompt string) time.Time {
	fmt.Print(prompt)

	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)

	if text == "" {
		return time.Time{}
	}

	// Example format: 2026-05-20T15:04:05
	t, err := time.Parse("2006-01-02T15:04:05", text)
	if err != nil {
		fmt.Println("Invalid time format")
		return time.Time{}
	}

	return t
}

func readOptionalTime(reader *bufio.Reader, prompt string) *time.Time {
	fmt.Print(prompt)

	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)

	if text == "" {
		return nil
	}

	// Example format: 2026-05-20T15:04:05
	t, err := time.Parse("2006-01-02T15:04:05", text)
	if err != nil {
		fmt.Println("Invalid time format")
		return nil
	}

	return &t
}

func readOptionalAssetType(reader *bufio.Reader, prompt string) *hummingbird.AssetType {
	fmt.Print(prompt)

	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)

	if text == "" {
		return nil
	}
	var assetType hummingbird.AssetType
	switch text {
	case "ingress":
		assetType = hummingbird.AssetType_Ingress
	case "egress":
		assetType = hummingbird.AssetType_Egress
	case "pair":
		assetType = hummingbird.AssetType_Interface_Pair
	}
	return &assetType
}

func main() {
	userInteraction()
}

type Asset struct {
	ID              uint64
	AssetType       hummingbird.AssetType
	IA              addr.IA
	Bandwidth       uint64
	StartAt         time.Time
	StopsAt         time.Time
	Price           uint64
	TimeGranularity uint64
	IfIdIngress     *uint32
	IfIdEgress      *uint32
}
