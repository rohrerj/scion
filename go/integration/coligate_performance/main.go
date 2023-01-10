// Copyright 2022 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"golang.org/x/net/ipv4"
	"golang.org/x/sync/errgroup"
)

var packetSize int = 300

func main() {
	defer log.HandlePanic()
	defer log.Flush()
	numProcs := int(math.Min(24, float64(runtime.NumCPU()/2)))
	fmt.Println("use numProcs", numProcs)
	runtime.GOMAXPROCS(numProcs)

	addFlags(&packetSize)
	flag.Parse()

	log.Info("Packet size", "packetSize", packetSize)
	fmt.Println("pktSize", packetSize)
	done := make(chan bool)
	startPromFetcher(done)
	err := initSender(uint16(packetSize))
	log.Error("error", "err", err)
	done <- true
	time.Sleep(100 * time.Millisecond)
}

func startPromFetcher(done chan bool) {
	httpClient := &http.Client{}
	metricsBuffer := make([]byte, 20000)
	ticker := time.NewTicker(1000 * time.Millisecond)
	os.Mkdir("metrics", os.ModePerm)
	go func() {
		defer log.HandlePanic()
		fullMap := make(map[string]map[string]float64)
	loop:
		for {
			select {
			case t := <-ticker.C:
				m := fetchMetrics(httpClient, metricsBuffer)
				for k, v := range m {
					dp, found := fullMap[k]
					if !found {
						dp = make(map[string]float64)
						fullMap[k] = dp
					}
					dp[strconv.Itoa(int(t.UnixMilli()%3600000))] = v
				}

			case <-done:
				ticker.Stop()
				break loop
			}
		}
		data, err := json.MarshalIndent(fullMap, "", "\t")
		if err != nil {
			integration.LogFatal("metrics", "err", err)
		}
		file, err := os.Create("metrics/data_" + strconv.Itoa(packetSize) + ".json")
		if err != nil {
			integration.LogFatal("metrics", "err", err)
		}
		file.Write(data)
		file.Close()
	}()
}

func fetchMetrics(httpClient *http.Client, buffer []byte) map[string]float64 {
	req, err := http.NewRequest("GET", "http://127.0.0.20:30458/metrics", nil)
	if err != nil {
		integration.LogFatal("metrics", "err", err)
	}
	res, err := httpClient.Do(req)
	if err != nil {
		integration.LogFatal("metrics", "err", err)
	}
	n, _ := res.Body.Read(buffer)
	res.Body.Close()
	str := strings.Split(string(buffer[:n]), "\n")
	m := make(map[string]float64)
	for _, s := range str {
		if !strings.HasPrefix(s, "#") && len(s) > 3 {
			kv := strings.Split(s, " ")
			val, err := strconv.ParseFloat(kv[1], 64)
			if err != nil {
				integration.LogFatal("metrics", "err", err)
			}
			m[kv[0]] = val
		}
	}
	return m
}

func initSender(pktSize uint16) error {
	g := &errgroup.Group{}
	for i := 0; i < 100; i++ {
		g.Go(func() error {
			return run(pktSize)
		})
	}
	return g.Wait()
}
func run(pktSize uint16) error {
	as, err := addr.ParseAS("ff00:0:110")
	if err != nil {
		return err
	}
	batchSize := 10
	writeMsgs := make([]ipv4.Message, batchSize)
	for i := 0; i < batchSize; i++ {
		writeMsgs[i].Buffers = [][]byte{make([]byte, 9000)}
	}
	pkt := &slayers.SCION{
		FlowID:     1,
		NextHdr:    17,
		HdrLen:     29,
		PayloadLen: pktSize,
		PathType:   colibri.PathType,
		DstIA:      addr.MustIAFrom(1, 1),
		SrcIA:      addr.MustIAFrom(1, as),
		RawDstAddr: []byte{177, 0, 0, 143},
		RawSrcAddr: []byte{177, 0, 7, 142},
		Path: &colibri.ColibriPath{
			InfoField: &colibri.InfoField{
				HFCount:     6,
				ResIdSuffix: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				BwCls:       50,
				OrigPayLen:  pktSize,
				ExpTick:     uint32(time.Date(2030, 1, 1, 0, 0, 0, 0, time.Local).Unix()) / 4,
			},
			PacketTimestamp: colibri.Timestamp{},
			HopFields: []*colibri.HopField{
				{
					IngressId: 0,
					EgressId:  1,
					Mac:       []byte{1, 2, 3, 4},
				},
				{
					IngressId: 1,
					EgressId:  2,
					Mac:       []byte{1, 2, 3, 4},
				},
				{
					IngressId: 1,
					EgressId:  2,
					Mac:       []byte{1, 2, 3, 4},
				},
				{
					IngressId: 1,
					EgressId:  2,
					Mac:       []byte{1, 2, 3, 4},
				},
				{
					IngressId: 1,
					EgressId:  2,
					Mac:       []byte{1, 2, 3, 4},
				},
				{
					IngressId: 1,
					EgressId:  2,
					Mac:       []byte{1, 2, 3, 4},
				},
			},
		},
		BaseLayer: slayers.BaseLayer{
			Payload: make([]byte, pktSize),
		},
	}

	buf := gopacket.NewSerializeBuffer()
	err = pkt.SerializeTo(buf, gopacket.SerializeOptions{})
	if err != nil {
		return err
	}
	rawPkt := buf.Bytes()
	payload := make([]byte, pktSize)
	for i := 0; i < batchSize; i++ {
		writeMsgs[i].Buffers[0] = append(rawPkt, payload...)
	}
	coligateAddr, err := net.ResolveUDPAddr("udp", "127.0.0.19:31006")
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, coligateAddr)
	if err != nil {
		return err
	}
	packetConn := ipv4.NewPacketConn(conn)
	defer packetConn.Close()

	startTime := time.Now()
	colibriPath := pkt.Path.(*colibri.ColibriPath)
	r := rand.New(rand.NewSource(rand.Int63()))
	for startTime.Add(30 * time.Second).After(time.Now()) {
		colibriPath.InfoField.ResIdSuffix[10] = byte(r.Intn(255))
		colibriPath.InfoField.ResIdSuffix[11] = byte(r.Intn(255))
		for i := 0; i < batchSize; i++ {
			colibriPath.SerializeTo(writeMsgs[i].Buffers[0][slayers.CmnHdrLen+pkt.AddrHdrLen():])
		}
		for i := 0; i < 100; i++ {
			packetConn.WriteBatch(writeMsgs, syscall.MSG_DONTWAIT)
		}
	}
	return nil
}

func addFlags(pktSize *int) {
	flag.IntVar(pktSize, "pktSize", 300, "pktSize")
}
