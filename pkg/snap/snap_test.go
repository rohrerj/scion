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

package snap_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/endhost"
	"github.com/scionproto/scion/pkg/endhost/token"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/app/appnet"
)

var anapaya_auth_key = ""

func TestFullEndhost(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
	defer cancelF()
	tokenProvider, err := token.NewAnapayaAuthProvider(ctx, anapaya_auth_key)
	if err != nil {
		t.Fatal(err)
	}
	endhostAPIURL := "https://s01.chgtg1.snap.anapaya.net:5001"
	connector, err := endhost.NewConnector(ctx, endhostAPIURL, endhost.WithTokenProvider(tokenProvider))
	if err != nil {
		t.Fatal(err)
	}
	defer connector.Close()
	sn := snet.SCIONNetwork{
		Topology:    connector.Topology,
		SCMPHandler: snet.DefaultSCMPHandler{},
	}
	dstIA := addr.MustParseIA("64-2:0:9")
	paths, err := connector.PathService.Paths(ctx, dstIA, endhost.WithSkipSegmentVerificationIfUnsupportedByAS())
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no paths")
	}
	remoteAddr, err := net.ResolveUDPAddr("udp", "129.132.175.104:30041")
	if err != nil {
		t.Fatal(err)
	}
	remote := &snet.UDPAddr{
		IA:   dstIA,
		Path: paths[0].Dataplane(),
		Host: remoteAddr,
	}
	s, err := sn.DialSnap(ctx, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.Write([]byte("testtesttesttest"))
	if err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 1024)
	s.SetReadDeadline(time.Now().Add(time.Second))
	n, err := s.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(resp[:n])
	t.Fail()
}

func TestQUICToMarketplace(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
	defer cancelF()
	tokenProvider, err := token.NewAnapayaAuthProvider(ctx, anapaya_auth_key)
	if err != nil {
		t.Fatal(err)
	}
	endhostAPIURL := "https://s01.chgtg1.snap.anapaya.net:5001"
	connector, err := endhost.NewConnector(ctx, endhostAPIURL, endhost.WithTokenProvider(tokenProvider))
	if err != nil {
		t.Fatal(err)
	}
	defer connector.Close()
	sn := snet.SCIONNetwork{
		Topology:    connector.Topology,
		SCMPHandler: snet.DefaultSCMPHandler{},
	}
	dstIA := addr.MustParseIA("64-2:0:9")
	paths, err := connector.PathService.Paths(ctx, dstIA, endhost.WithSkipSegmentVerificationIfUnsupportedByAS())
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no paths")
	}
	remoteAddr, err := net.ResolveUDPAddr("udp", "129.132.121.169:8888")
	if err != nil {
		t.Fatal(err)
	}
	remote := &snet.UDPAddr{
		IA:   dstIA,
		Path: paths[0].Dataplane(),
		Host: remoteAddr,
	}
	//
	client, err := sn.ListenSnap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clientTransport := &quic.Transport{
		Conn: client,
	}
	//
	dialerFunc := (&squic.EarlyDialerFactory{
		Transport: clientTransport,
		TLSConfig: &tls.Config{
			NextProtos: []string{"h3", "SCION"},
			ServerName: "scion-marketplace.netsec.ethz.ch",
		},
		Rewriter: &appnet.AddressRewriter{
			Router: &snet.BaseRouter{
				Querier: connector.PathService,
			},
		},
		QUICConfig: &quic.Config{
			InitialPacketSize: 1200,
		},
	}).NewDialer
	dialer := dialerFunc(remote)
	httpClient := libconnect.HTTPClient{
		RoundTripper: &http3.Transport{
			Dial: dialer.DialEarly,
		},
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	testValue := make([]byte, 1000)
	for i := range testValue {
		testValue[i] = 'a'
	}
	form := url.Values{}
	form.Set("username", "Alice")
	form.Set("password", "")
	form.Set("test", string(testValue))
	loginURL, _ := url.Parse("https://scion-marketplace.netsec.ethz.ch:8888/login")
	loginReq, err := http.NewRequest(
		http.MethodPost,
		loginURL.String(),
		bytes.NewBufferString(form.Encode()),
	)
	if err != nil {
		panic(err)
	}
	loginReq.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)
	loginResp, err := httpClient.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	defer loginResp.Body.Close()
	jar.SetCookies(loginURL, loginResp.Cookies())
	fmt.Println("login cookies:", jar.Cookies(loginURL))

	apiURL, _ := url.Parse("https://scion-marketplace.netsec.ethz.ch:8888/assets")

	apiReq, err := http.NewRequest(
		http.MethodGet,
		apiURL.String(),
		nil,
	)
	if err != nil {
		panic(err)
	}

	for _, c := range jar.Cookies(apiURL) {
		apiReq.AddCookie(c)
	}

	apiResp, err := httpClient.Do(apiReq)
	if err != nil {
		panic(err)
	}
	defer apiResp.Body.Close()
	content, err := io.ReadAll(apiResp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(content))
	t.Fail()
}
