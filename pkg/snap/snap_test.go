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
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/endhost"
	"github.com/scionproto/scion/pkg/snap"
)

func TestSnap(t *testing.T) {
	/*snapControlURL := "http://s01.chgtg1.snap.anapaya.net:5001"
	token := "REDACTED"
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
	defer cancelF()
	t.Fail()*/
}

func TestFullEndhost(t *testing.T) {
	endhostAPIURL := "http://93.185.219.2:5001"
	token := ""
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
	defer cancelF()
	connector, err := endhost.NewConnector(ctx, endhostAPIURL)
	if err != nil {
		t.Fatal(err)
	}
	underlays, err := connector.UnderlayService.ListUnderlays(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if underlays.Snap == nil {
		t.Fatal("snap is nil")
	}
	var targetSnap endhost.Snap
	for _, snap := range underlays.Snap.Snaps {
		fmt.Println(snap.Address, snap.IsdASes)
		if snap.Address == "http://93.185.219.2:5001/" {
			targetSnap = snap
		}
	}
	fmt.Println(targetSnap)
	dstIA := addr.MustParseIA("64-2:0:9")
	paths, err := connector.PathService.Paths(ctx, dstIA, connector.Topology.LocalIA)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no paths")
	}
	snapApi := connector.Topology.SnapApi

	snapTunLocalIP := netip.MustParseAddr("127.0.0.10")
	tunnel, err := snap.NewSnapTunnel(ctx, snapApi, token, snapTunLocalIP)
	if err != nil {
		t.Fatal(err)
	}
	/*sn := snet.SCIONNetwork{
		Topology: connector.Topology,
	}
	// localAddr must be in tunnel namespace, not system loopback
	localAddr, err := net.ResolveUDPAddr("udp", "127.0.0.10:8888")
	if err != nil {
		t.Fatal(err)
	}
	remoteAddr, err := net.ResolveUDPAddr("udp", "129.132.175.104:30041")
	if err != nil {
		t.Fatal(err)
	}
	// nextHop is the tunnel gateway - use the tunnel's local IP itself
	nextHop, err := net.ResolveUDPAddr("udp", "127.0.0.10:30041")
	if err != nil {
		t.Fatal(err)
	}
	remote := &snet.UDPAddr{
		IA:      dstIA,
		Path:    paths[0].Dataplane(),
		NextHop: nextHop,
		Host:    remoteAddr,
	}
	conn, err := sn.DialSnap(ctx, tunnel, localAddr, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = conn.Write([]byte("helloworld"))
	if err != nil {
		t.Fatal(err)
	}*/
	time.Sleep(time.Second)
	fmt.Println("Metrics")
	fmt.Println(tunnel.Metrics())

	t.Fail()
}
