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
	"log"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/endhost"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snap"
	"github.com/scionproto/scion/pkg/snet"
)

func TestSnap(t *testing.T) {
	/*snapControlURL := "http://s01.chgtg1.snap.anapaya.net:5001"
	token := "REDACTED"
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
	defer cancelF()
	t.Fail()*/
}

func TestFullEndhost(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
	defer cancelF()
	token := ""
	endhostAPIURL := "http://93.185.219.2:5001"
	connector, err := endhost.NewConnector(ctx, endhostAPIURL, endhost.WithToken(token))
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
	snapApi := connector.Topology.Snap.ControlApi

	tunnel, err := snap.NewSnapTunnel(ctx, snapApi, token)
	if err != nil {
		t.Fatal(err)
	}
	remoteAddr, err := net.ResolveUDPAddr("udp", "129.132.175.104:30041")
	if err != nil {
		t.Fatal(err)
	}
	// localAddr must be in tunnel namespace, not system loopback
	localAddr, err := net.ResolveUDPAddr("udp", "188.60.224.160:8888")
	if err != nil {
		t.Fatal(err)
	}

	pkt := snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   connector.Topology.LocalIA,
				Host: addr.HostIP(localAddr.AddrPort().Addr()),
			},
			Destination: snet.SCIONAddress{
				IA:   addr.MustParseIA("64-2:0:9"),
				Host: addr.HostIP(remoteAddr.AddrPort().Addr()),
			},
			Path: paths[0].Dataplane(),
			Payload: snet.UDPPayload{
				SrcPort: 8888,
				DstPort: 30041,
				Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
		},
		Bytes: make(snet.Bytes, 1024),
	}
	err = pkt.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	tunnel.SendChannel() <- pkt.Bytes
	var buf []byte
	select {
	case buf = <-tunnel.ReceiveChannel():
	case <-time.After(time.Second):
		t.Log("no response")
		t.Fail()
		return
	}

	udpLayer := slayers.UDP{}
	scionLayer := slayers.SCION{}
	scmpLayer := slayers.SCMP{}
	_, err = decodeLayers(buf, &scionLayer, &scmpLayer, &udpLayer)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("scmp type code", scmpLayer.TypeCode)

	fmt.Println("received", buf)
	time.Sleep(time.Second)
	/*b, err := conn.WriteTo([]byte("helloworld"), tunnel.DataplaneAddr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("written %d bytes\n", b)
	time.Sleep(time.Second)
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	b, raddr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("packet from remote %v packet:\n%v\n", raddr, buf[:b])*/

	t.Fail()
}

func decodeLayers(data []byte, base gopacket.DecodingLayer,
	opts ...gopacket.DecodingLayer) (gopacket.DecodingLayer, error) {

	if err := base.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}
	last := base
	for _, opt := range opts {
		if opt.CanDecode().Contains(last.NextLayerType()) {
			data := last.LayerPayload()
			if err := opt.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				return nil, err
			}
			last = opt
		}
	}
	return last, nil
}

/*sn := snet.SCIONNetwork{
	Topology: connector.Topology,
}*/
/*remoteAddr, err := net.ResolveUDPAddr("udp", "129.132.175.104:30041")
if err != nil {
	t.Fatal(err)
}*/
// nextHop is the tunnel gateway - use the tunnel's local IP itself
/*nextHop, err := net.ResolveUDPAddr("udp", "127.0.0.10:30000")
if err != nil {
	t.Fatal(err)
}*/
/*remote := &snet.UDPAddr{
	IA:      dstIA,
	Path:    paths[0].Dataplane(),
	NextHop: tunnel.DataplaneAddr,
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
}
buf := make([]byte, 1024)
conn.SetReadDeadline(time.Now().Add(time.Second * 2))
_, err = conn.Read(buf)
if err != nil {
	t.Fatal(err)
}
time.Sleep(time.Second)
fmt.Println("Metrics")
fmt.Println(tunnel.Metrics())
*/
