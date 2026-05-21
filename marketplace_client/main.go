package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
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
	fmt.Println("-> redeem")
	fmt.Println("-> reservation")
	fmt.Println("-> exit")
}

func userInteraction(url string, token string) {
	reader := bufio.NewReader(os.Stdin)
	client := hummingbirdconnect.NewMarketplaceServiceClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}, url, connect.WithInterceptors(authInterceptor(token)))
	ctx := context.Background()
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
				return
			}
			fmt.Printf("Bought assets for a total cost of %d\n", rep.Msg.Cost)
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
			IfIdIngress:     asset.IfIdEgress,
			IfIdEgress:      asset.IfIdIngress,
			TimeGranularity: asset.TimeGranularity,
		})
	}
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
	args := os.Args
	if len(args) != 3 {
		fmt.Printf("%s <marketplace_api_url> <jwt_token>\n", args[0])
		return
	}
	url := args[1]
	jwtToken := args[2]
	//marketUrl := "https://localhost:8888"
	userInteraction(url, jwtToken)
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
