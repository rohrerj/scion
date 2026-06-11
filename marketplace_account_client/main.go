package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/endhost"
	"github.com/scionproto/scion/pkg/hummingbird/registration"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/trust"
)

type Querier struct {
	Connector *endhost.Connector
}

func (q *Querier) Query(ctx context.Context, ia addr.IA) ([]snet.Path, error) {
	return q.Connector.PathService.Paths(ctx, ia, q.Connector.Topology.LocalIA)
}

func withSCION(ctx context.Context, endhostAPI string, remote *snet.UDPAddr, localIA addr.IA) (
	hummingbirdconnect.AccountServiceClient, error) {

	connector, err := endhost.NewConnector(ctx, endhostAPI, endhost.WithLocalIA(localIA))
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
	client := hummingbirdconnect.NewAccountServiceClient(
		libconnect.HTTPClient{
			RoundTripper: &http3.Transport{
				Dial: dialer.DialEarly,
			},
		}, libconnect.BaseUrl(remote))
	return client, nil
}

var insecure bool

func main() {
	flag.BoolVar(&insecure, "insecure", false, "indicates whether TLS insecure skip verify should be applied")
	flag.Parse()
	reader := bufio.NewReader(os.Stdin)
	ctx := context.Background()
	url := readString(reader, "marketplace_account_api: ")
	var client hummingbirdconnect.AccountServiceClient
	urlSplit := strings.Split(url, "://")
	var httpHost string
	api := ""
	if len(urlSplit) == 1 {
		api = urlSplit[0]
	} else if len(urlSplit) == 2 {
		api = urlSplit[1]
		httpHost = api
	} else {
		fmt.Println("invalid url", url)
		return
	}
	localIAString := readString(reader, "local IA: ")
	localIA, err := addr.ParseIA(localIAString)
	if err != nil {
		fmt.Println(err)
		return
	}
	scionAddr, port, err := addr.ParseAddrPort(api)
	if err == nil {
		remote := &snet.UDPAddr{
			IA:   scionAddr.IA,
			Host: net.UDPAddrFromAddrPort(netip.AddrPortFrom(scionAddr.Host.IP(), port)),
		}
		baseUrlSplit := strings.Split(libconnect.BaseUrl(remote), "https://")
		if len(baseUrlSplit) != 2 {
			fmt.Println("base Url is invalid", baseUrlSplit)
			return
		}
		httpHost = baseUrlSplit[1]
		endhostApi := readString(reader, "endhostAPI: ")
		if endhostApi == "" {
			fmt.Println("invalid endhost API")
			return
		}
		client, err = withSCION(ctx, endhostApi, remote, localIA)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("use SCION connection")
	} else {
		if insecure {
			client = hummingbirdconnect.NewAccountServiceClient(&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}, url)
		} else {
			client = hummingbirdconnect.NewAccountServiceClient(http.DefaultClient, url)
		}
		fmt.Println("use TCP connection")
	}
	trcDir := readString(reader, "trc directory: ")
	certDir := readString(reader, "certificate directory: ")
	keyRingDir := readString(reader, "keyring directory: ")
	regClient := registration.NewClient(client, httpHost)
	publisherToken, redemptionToken, err := regClient.RegisterWithNewSigner(ctx, localIA, trcDir, certDir, keyRingDir)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Publisher Token: %s\nRedemptionService Token: %s\n", publisherToken, redemptionToken)
}

func readString(reader *bufio.Reader, prompt string) string {
	fmt.Print(prompt)

	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)

	return text
}
