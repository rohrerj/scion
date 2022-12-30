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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	libcol "github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/daemon"
	dkfetcher "github.com/scionproto/scion/go/lib/drkey/fetcher"
	libint "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/grpc"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/resolver"
)

var packetSize int = 300

func main() {
	if err := realMain(); err != nil {
		os.Exit(-1)
	}
}

func realMain() error {
	defer log.HandlePanic()
	defer log.Flush()
	runtime.GOMAXPROCS(2)

	var remote snet.UDPAddr
	var timeout = util.DurWrap{Duration: 3 * time.Second}
	addFlags(&remote, &timeout, &packetSize)
	log.Info("Packet size", "packetSize", packetSize)
	integration.Setup()
	defer integration.Done(integration.Local.IA, remote.IA)
	if integration.Mode == integration.ModeServer {
		return initReceiver(timeout)
	} else if integration.Mode == integration.ModeClient && integration.Local.IA.String() == "1-ff00:0:110" && remote.IA.String() == "1-ff00:0:111" {
		pair := fmt.Sprintf("%s -> %s", integration.Local.IA, remote.IA)
		log.Info("Starting", "pair", pair)
		if integration.Local.IA.Equal(remote.IA) {
			log.Info("Skip local test")
			return nil
		}
		done := make(chan bool)
		startPromFetcher(done)
		err := initSender(remote, timeout)
		done <- true
		time.Sleep(100 * time.Millisecond)
		return err //
	} else {
		log.Debug("Invalid IA selection", "Mode", integration.Mode, "IA", integration.Local.IA.String())
		return nil
	}

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

func initSender(remote snet.UDPAddr, timeout util.DurWrap) error {
	startTime := time.Now()
	numGoRoutines := 100
	g, _ := errgroup.WithContext(context.Background())
	for i := 0; i < numGoRoutines; i++ {
		g.Go(func() error {
			for startTime.Add(30 * time.Second).After(time.Now()) {
				sdConn := integration.SDConn()
				if sdConn == nil {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				client := newClient(
					sdConn,
					timeout.Duration,
					remote.Copy(),
				)
				if err := client.run(); err != nil {
					log.Error("err", "err", err)
					time.Sleep(10 * time.Millisecond)
				}
				sdConn.Close(context.Background())
			}
			return nil
		})
		time.Sleep(10 * time.Millisecond)
	}
	err := g.Wait()
	if err != nil {
		integration.LogFatal("ERROR", "err", err)
	}
	return err
}

func initReceiver(timeout util.DurWrap) error {
	log.Info("Starting server", "isd_as", integration.Local.IA)
	defer log.Info("Finished server", "isd_as", integration.Local.IA)

	dispatcher := reliable.NewDispatcher(reliable.DefaultDispPath)
	scionNet := &snet.SCIONNetwork{
		LocalIA: integration.Local.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher: dispatcher,
			SCMPHandler: &snet.DefaultSCMPHandler{
				RevocationHandler: daemon.RevHandler{
					Connector: integration.SDConn(),
				},
			},
		},
	}
	conn, err := scionNet.Listen(context.Background(), "udp", integration.Local.Host, addr.SvcNone)
	if err != nil {
		integration.LogFatal("Error listening", "err", err)
	}
	defer conn.Close()

	if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
		addr, err := net.ResolveUDPAddr("udp", conn.LocalAddr().String())
		if err != nil {
			log.Error("unable to parse listening address", "err", err)
		}
		fmt.Printf("Port=%d\n", addr.Port)
		fmt.Printf("%s%s\n\n", libint.ReadySignal, integration.Local.IA)
	}
	log.Info("Listening", "local", conn.LocalAddr().String())
	s := &server{
		Timeout: timeout.Duration,
	}
	go func() {
		defer log.HandlePanic()
		s.allowAdmission(integration.SDConn(), integration.Local.Host.IP)
	}()
	buffer := make([]byte, packetSize)
	for {
		if err := s.accept(conn, buffer); err != nil {
			integration.LogFatal("accepting connection", "err", err)
		}
	}
}

type server struct {
	Timeout time.Duration
}

func (s server) allowAdmission(daemon daemon.Connector, serverIP net.IP) {
	for {
		ctx, cancelF := context.WithTimeout(context.Background(), s.Timeout)
		entry := &libcol.AdmissionEntry{
			DstHost:         serverIP, // could be empty to detect it automatically
			ValidUntil:      time.Now().Add(1 * time.Minute),
			RegexpIA:        "", // from any AS
			RegexpHost:      "", // from any host
			AcceptAdmission: true,
		}
		log.Debug("server, adding admission entry", "ip", serverIP)
		validUntil, err := daemon.ColibriAddAdmissionEntry(ctx, entry)
		if err != nil {
			integration.LogFatal("establishing admission from server", "err", err)
		}
		if time.Until(validUntil).Seconds() < 45 {
			integration.LogFatal("too short validity, something went wrong",
				"requested", entry.ValidUntil, "got", validUntil)
		}
		cancelF()
		time.Sleep(30 * time.Second)
	}
}

func (s server) accept(conn *snet.Conn, buffer []byte) error {
	_, from, err := conn.ReadFrom(buffer)
	if err != nil {
		return err
	}
	_, ok := from.(*snet.UDPAddr)
	if !ok {
		return serrors.New("not a scion address", "addr", from)
	}
	return nil
}

func (c client) run() error {
	startTime := time.Now()

	ctx, cancelF := context.WithTimeout(context.Background(), c.Timeout)
	defer cancelF()
	deadline, _ := ctx.Deadline()

	// find a path to the destination
	pathquerier := daemon.Querier{
		Connector: c.Daemon,
		IA:        integration.Local.IA,
	}
	pathsToDst, err := pathquerier.Query(ctx, c.Remote.IA)
	if err != nil {
		log.Error("obtaining paths", "err", err)
		return err
	}
	if len(pathsToDst) == 0 {
		log.Error("no paths found")
		return err
	}
	pathToDst := pathsToDst[0]
	log.Debug("found path to destination", "path", pathToDst)
	c.Remote.Path = pathToDst.Dataplane()
	c.Remote.NextHop = pathToDst.UnderlayNextHop()
	// dial to destination using the first path
	dispatcher := reliable.NewDispatcher(reliable.DefaultDispPath)
	scionNet := &snet.SCIONNetwork{
		LocalIA: integration.Local.IA,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher: dispatcher,
			SCMPHandler: &snet.DefaultSCMPHandler{
				RevocationHandler: daemon.RevHandler{
					Connector: c.Daemon,
				},
			},
		},
		Metrics: c.Metrics,
	}
	log.Debug("dialing with best effort", "addr", c.Remote.String(), "path", c.Remote.Path)
	conn, err := scionNet.Dial(ctx, "udp", integration.Local.Host, c.Remote, addr.SvcNone)
	if err != nil {
		log.Error("dialing", "err", err)
		return err
	}
	err = conn.SetDeadline(deadline)
	if err != nil {
		log.Error("setting deadline", "err", err)
		return err
	}

	stitchable, err := c.listRsvs(ctx)
	if err != nil {
		log.Error("listing reservations", "err", err)
		return err
	}
	log.Debug("listed reservations", "list", stitchable.String())
	trips := libcol.CombineAll(stitchable)
	log.Info("computed full trips", "count", len(trips))
	if len(trips) == 0 {
		log.Error("no trips found")
		return err
	}
	// obtain a reservation
	_, p, err := c.createRsv(ctx, trips[0], 40)
	if err != nil {
		log.Error("creating reservation", "err", err)
		return err
	}
	c.Remote.Path = p.Dataplane()
	c.Remote.NextHop = p.UnderlayNextHop()
	time.Sleep(100 * time.Millisecond)
	for startTime.Add(5 * time.Second).After(time.Now()) {
		for i := 0; i < 100; i++ {
			if err := c.sendPacket(conn); err != nil {
				log.Error("error while sending packet", "err", err)
			}
		}
		//time.Sleep(1 * time.Millisecond)

	}
	conn.Close()
	return nil
}

func (c *client) sendPacket(conn *snet.Conn) error {
	//packetSize := newPacketSize(100, 100)
	buf := make([]byte, packetSize)
	_, err := conn.WriteTo(buf, c.Remote)
	return err
}

func addFlags(remote *snet.UDPAddr, timeout *util.DurWrap, pktSize *int) {
	flag.Var(remote, "remote", "(Mandatory for clients) address to connect to")
	flag.Var(timeout, "timeout", `The timeout for each attempt (default "3s")`)
	flag.IntVar(pktSize, "pktSize", 300, "pktSize")
}

type client struct {
	Daemon       daemon.Connector
	DRKeyFetcher *dkfetcher.FromCS
	Timeout      time.Duration
	Metrics      snet.SCIONNetworkMetrics
	Local        *snet.UDPAddr
	Remote       *snet.UDPAddr
}

/*func newPacketSize(standardDerivation float64, desiredMean float64) int {
	size := rand.NormFloat64()
	size *= standardDerivation
	size += desiredMean
	if size < 0 {
		size *= -1
	}
	return int(size)
}*/

func newClient(daemon daemon.Connector, timeout time.Duration, remoteAddr *snet.UDPAddr) *client {
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelF()

	addrMap, err := daemon.SVCInfo(ctx, []addr.HostSVC{addr.SvcCS})
	if err != nil {
		integration.LogFatal("cannot obtain info about the CS")
	}
	addrs := make([]resolver.Address, 1)
	addrs[0] = resolver.Address{
		Addr: addrMap[addr.SvcCS],
	}
	grpcDialer := &grpc.TCPDialer{
		LocalAddr: &net.TCPAddr{
			IP: integration.Local.Host.IP,
		},
		SvcResolver: func(hs addr.HostSVC) []resolver.Address {
			return addrs
		},
	}
	return &client{
		Daemon: daemon,
		DRKeyFetcher: &dkfetcher.FromCS{
			Dialer: grpcDialer,
		},
		Timeout: timeout,
		Local:   &integration.Local,
		Remote:  remoteAddr,
	}
}

func (c client) listRsvs(ctx context.Context) (
	*libcol.StitchableSegments, error) {
	for {
		stitchable, err := c.Daemon.ColibriListRsvs(ctx, c.Remote.IA)
		if err != nil {
			return nil, err
		}
		if stitchable != nil {
			return stitchable, nil
		}
		time.Sleep(time.Second)
	}
}

func (c client) createRsv(ctx context.Context, fullTrip *libcol.FullTrip,
	requestBW reservation.BWCls) (reservation.ID, snet.Path, error) {

	now := time.Now()
	setupReq, err := libcol.NewReservation(ctx, c.DRKeyFetcher, fullTrip, c.Local.Host.IP,
		c.Remote.Host.IP, requestBW)
	if err != nil {
		return reservation.ID{}, nil, err
	}
	res, err := c.Daemon.ColibriSetupRsv(ctx, setupReq)
	if err != nil {
		return reservation.ID{}, nil, err
	}
	err = res.ValidateAuthenticators(ctx, c.DRKeyFetcher, fullTrip.PathSteps(), c.Local.Host.IP, now)
	if err != nil {
		return reservation.ID{}, nil, err
	}
	return setupReq.Id, res.ColibriPath, nil
}
