// Copyright 2022 ETH Zurich
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

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/scionproto/scion/go/integration"
	"github.com/scionproto/scion/go/lib/addr"
	libcol "github.com/scionproto/scion/go/lib/colibri"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/daemon"
	dkfetcher "github.com/scionproto/scion/go/lib/drkey/fetcher"
	libint "github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/metrics"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/grpc"
	"google.golang.org/grpc/resolver"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.HandlePanic()
	defer log.Flush()

	var remote snet.UDPAddr
	var timeout = util.DurWrap{Duration: 3 * time.Second}
	addFlags(&remote, &timeout)
	integration.Setup()

	closeTracer, err := integration.InitTracer("end2end-" + integration.Mode)
	if err != nil {
		log.Error("Tracer initialization failed", "err", err)
		return 1
	}
	defer closeTracer()

	scionConnMetrics := metrics.NewSCIONNetworkMetrics()

	if integration.Mode == integration.ModeServer {
		server{
			Timeout: timeout.Duration,
			Metrics: scionConnMetrics,
		}.run()
		return 0
	}
	pair := fmt.Sprintf("%s -> %s", integration.Local.IA, remote.IA)
	log.Info("Starting", "pair", pair)
	defer log.Info("Finished", "pair", pair)
	defer integration.Done(integration.Local.IA, remote.IA)

	if integration.Local.IA.Equal(remote.IA) {
		log.Info("dst == src! Skipping test inside local AS")
		return 0
	}
	fs := []func(c client, conn *snet.Conn, messagePayload []byte, recBuff []byte,
		trips []*libcol.FullTrip, resID reservation.ID){
		generalTest,
		invalidReservationTest,
		exceedBandwidthTest,
		renewReservationTest,
		invalidIndexTest,
		invalidBwClTest,
	}
	for _, f := range fs {
		log.Info("Execute", "func", runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name())
		c := *newClient(
			integration.SDConn(),
			timeout.Duration,
			scionConnMetrics,
			&remote,
		)
		c.run(f)
	}
	return 0
}

func addFlags(remote *snet.UDPAddr, timeout *util.DurWrap) {
	flag.Var(remote, "remote", "(Mandatory for clients) address to connect to")
	flag.Var(timeout, "timeout", `The timeout for each attempt (default "3s")`)
}

type server struct {
	Timeout time.Duration
	Metrics snet.SCIONNetworkMetrics
}

func (s server) run() {
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
		Metrics: s.Metrics,
	}
	conn, err := scionNet.Listen(context.Background(), "udp", integration.Local.Host, addr.SvcNone)
	if err != nil {
		integration.LogFatal("Error listening", "err", err)
	}

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

	go func() {
		defer log.HandlePanic()
		s.allowAdmission(integration.SDConn(), integration.Local.Host.IP)
	}()
	for {
		buffer := make([]byte, 16384)
		if err := s.accept(conn, buffer); err != nil {
			integration.LogFatal("accepting connection", "err", err)
		}
	}
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
	n, from, err := conn.ReadFrom(buffer)
	if err != nil {
		return err
	}
	fromScion, ok := from.(*snet.UDPAddr)
	if !ok {
		return serrors.New("not a scion address", "addr", from)
	}

	data := buffer[:n]
	if strings.HasPrefix(string(data), "Coligate Integration Test") {
		log.Info("received coligate pattern", "sender", fromScion.String())
		n2, err := conn.WriteTo(data, from)
		if err != nil {
			return serrors.WrapStr("writing echo response from server", err)
		}
		if n2 != len(data) {
			return serrors.New("wrong size writing", "data_len", len(data), "written", n2)
		}
	} else {
		return serrors.New("unknown received pattern", "pattern", string(data),
			"hex", hex.EncodeToString(data))
	}

	return nil
}

type client struct {
	Daemon       daemon.Connector
	DRKeyFetcher *dkfetcher.FromCS
	Timeout      time.Duration
	Metrics      snet.SCIONNetworkMetrics
	Local        *snet.UDPAddr
	Remote       *snet.UDPAddr
}

func newClient(daemon daemon.Connector, timeout time.Duration, metrics snet.SCIONNetworkMetrics,
	remoteAddr *snet.UDPAddr) *client {

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
		Metrics: metrics,
		Local:   &integration.Local,
		Remote:  remoteAddr,
	}
}

func (c client) run(f func(c client, conn *snet.Conn, messagePayload []byte,
	recBuff []byte, trips []*libcol.FullTrip, resID reservation.ID)) {

	ctx, cancelF := context.WithTimeout(context.Background(), c.Timeout)
	defer cancelF()
	deadline, _ := ctx.Deadline()

	// find a path to the destination
	pathquerier := daemon.Querier{
		Connector: integration.SDConn(),
		IA:        integration.Local.IA,
	}
	pathsToDst, err := pathquerier.Query(ctx, c.Remote.IA)
	if err != nil {
		integration.LogFatal("obtaining paths", "err", err)
	}
	if len(pathsToDst) == 0 {
		integration.LogFatal("no paths found")
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
					Connector: integration.SDConn(),
				},
			},
		},
		Metrics: c.Metrics,
	}
	log.Debug("dialing with best effort", "addr", c.Remote.String(), "path", c.Remote.Path)
	conn, err := scionNet.Dial(ctx, "udp", integration.Local.Host, c.Remote, addr.SvcNone)
	if err != nil {
		integration.LogFatal("dialing", "err", err)
	}
	err = conn.SetDeadline(deadline)
	if err != nil {
		integration.LogFatal("setting deadline", "err", err)
	}
	stitchable, err := c.listRsvs(ctx)
	if err != nil {
		integration.LogFatal("listing reservations", "err", err)
	}
	log.Debug("listed reservations", "list", stitchable.String())
	trips := libcol.CombineAll(stitchable)
	log.Debug("computed full trips", "count", len(trips))
	if len(trips) == 0 {
		integration.LogFatal("no trips found")
	}
	// obtain a reservation
	resID, p, err := c.createRsv(ctx, trips[0], 1)
	if err != nil {
		integration.LogFatal("creating reservation", "err", err)
	}

	// use the reservation
	c.Remote.Path = p.Dataplane()
	// NextHop is the address of the colibri gateway
	c.Remote.NextHop = p.UnderlayNextHop()

	log.Debug("Colibri Gateway address:", "NextHop", c.Remote.NextHop)

	messagePayload := []byte("Coligate Integration Test " + c.Local.IA.String())
	recBuff := make([]byte, 128)
	time.Sleep(100 * time.Millisecond)

	f(c, conn, messagePayload, recBuff, trips, resID)
}

// Tests that the data packet has correctly reached the other endhost and that the
// other endhost responded with a colibri packet.
func generalTest(c client, conn *snet.Conn, messagePayload []byte, recBuff []byte,
	trips []*libcol.FullTrip, resID reservation.ID) {

	_, err := conn.WriteTo(messagePayload, c.Remote)
	if err != nil {
		integration.LogFatal("writing data with colibri", "err", err)
	}
	// read echo back again
	l, raddr, err := conn.ReadFrom(recBuff)
	if err != nil {
		integration.LogFatal("reading data", "err", err)
	}
	sraddr, ok := raddr.(*snet.UDPAddr)
	if !ok {
		integration.LogFatal("sender of response is not scion", "raddr", raddr,
			"type", common.TypeOf(raddr))
	}
	sraddrPath, _ := sraddr.GetPath()
	sraddrRawPath, gotColPath := sraddrPath.Dataplane().(path.Colibri)
	if !gotColPath {
		sraddrReplyPath, ok := sraddrPath.Dataplane().(snet.RawReplyPath)
		if ok {
			colPath, ok := sraddrReplyPath.Path.(*colpath.ColibriPathMinimal)
			if ok {
				sraddrRawPath = path.Colibri{
					Raw: make([]byte, colPath.Len()),
				}
				if err := colPath.SerializeTo(sraddrRawPath.Raw); err != nil {
					integration.LogFatal("cannot serialize colibri path", "err", err)
				}
				gotColPath = true
			}
		}
	}
	if !gotColPath {
		integration.LogFatal("non-colibri path type", "type", common.TypeOf(sraddrPath.Dataplane()))
	}
	if sraddrRawPath.Raw == nil {
		integration.LogFatal("colibri path but empty raw", "path", sraddrRawPath)
	}
	if string(recBuff[:l]) != string(messagePayload) {
		integration.LogFatal("Received incorrect response from server", "expected",
			messagePayload, "actual", string(recBuff[:l]))
	}
	log.Info("Received correct response from server", "msg", messagePayload)
}

// Tests that no data packet can be sent over the colibri gateway with an invalid reservation.
func invalidReservationTest(c client, conn *snet.Conn, messagePayload []byte,
	recBuff []byte, trips []*libcol.FullTrip, resID reservation.ID) {

	s := &colpath.ColibriPathMinimal{}
	err := s.DecodeFromBytes(c.Remote.Path.(path.Colibri).Raw)
	if err != nil {
		integration.LogFatal("DecodeFromBytes", "err", err)
	}
	s.InfoField.ResIdSuffix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	err = s.SerializeTo(c.Remote.Path.(path.Colibri).Raw)
	if err != nil {
		integration.LogFatal("SerializeTo", "err", err)
	}
	_, err = conn.WriteTo(messagePayload, c.Remote)
	if err != nil {
		integration.LogFatal("writing data with colibri", "err", err)
	}
	conn.SetReadDeadline(time.Now().Add(c.Timeout))
	_, _, err = conn.ReadFrom(recBuff)
	if err == nil {
		integration.LogFatal("reading data", "err", err)
	}
}

// Tests that packets that exceed the bandwidth are dropped. The reservation uses
// bandwidth class 1, which allows 2000 bytes per second, including the headers. The
// burst size is also 2000 bytes. If we send two times a packet with payload size
// 1200 bytes the first one should be accepted and the second one dropped.
func exceedBandwidthTest(c client, conn *snet.Conn, messagePayload []byte,
	recBuff []byte, trips []*libcol.FullTrip, resID reservation.ID) {

	time.Sleep(1 * time.Second) // Make sure we have the full bandwidth available
	sendBuf := make([]byte, 1200-len(messagePayload))
	messagePayload = append(messagePayload, sendBuf...)

	_, err := conn.WriteTo(messagePayload, c.Remote)
	if err != nil {
		integration.LogFatal("writing data with colibri", "err", err)
	}
	_, err = conn.WriteTo(messagePayload, c.Remote)
	if err != nil {
		integration.LogFatal("writing data with colibri", "err", err)
	}

	conn.SetReadDeadline(time.Now().Add(c.Timeout))
	// The first packet should have reached the other endhost because the bandwidth has
	// not been exceeded yet and therefore we should get a response.
	_, _, err = conn.ReadFrom(recBuff)
	if err != nil {
		integration.LogFatal("reading data", "err", err)
	}
	// The second packet should not have reached the other endhost because now we have
	// exceeded the bandwidth and therefore we should not get a response.
	_, _, err = conn.ReadFrom(recBuff)
	if err == nil {
		integration.LogFatal("reading data", "err", err)
	}
}

// Tests that we can send a data packet over the colibri gateway with another valid
// reservation index.
func renewReservationTest(c client, conn *snet.Conn, messagePayload []byte,
	recBuff []byte, trips []*libcol.FullTrip, resID reservation.ID) {

	ctx, cancelF := context.WithTimeout(context.Background(), c.Timeout)
	defer cancelF()
	_, err := c.renewRsv(ctx, trips[0], 1, resID, 1)
	if err != nil {
		integration.LogFatal("Reservation renewal failed", "err", err)
	}
	_, err = conn.WriteTo(messagePayload, c.Remote)
	if err != nil {
		integration.LogFatal("writing data with colibri", "err", err)
	}
	_, _, err = conn.ReadFrom(recBuff)
	if err != nil {
		integration.LogFatal("reading data", "err", err)
	}
}

// Tests that no packets with a valid reservation id but invalid reservation index
// can be sent over the colibri gateway.
func invalidIndexTest(c client, conn *snet.Conn, messagePayload []byte,
	recBuff []byte, trips []*libcol.FullTrip, resID reservation.ID) {

	s := &colpath.ColibriPathMinimal{}
	err := s.DecodeFromBytes(c.Remote.Path.(path.Colibri).Raw)
	if err != nil {
		integration.LogFatal("DecodeFromBytes", "err", err)
	}
	s.InfoField.Ver = 100
	err = s.SerializeTo(c.Remote.Path.(path.Colibri).Raw)
	if err != nil {
		integration.LogFatal("SerializeTo", "err", err)
	}
	_, err = conn.WriteTo(messagePayload, c.Remote)
	if err != nil {
		integration.LogFatal("writing data with colibri", "err", err)
	}
	conn.SetReadDeadline(time.Now().Add(c.Timeout))
	_, _, err = conn.ReadFrom(recBuff)
	if err == nil {
		integration.LogFatal("reading data", "err", err)
	}
}

// Tests that a packet which contains a bandwidth class which is different to
// the bandwidth class of the reservation is dropped.
func invalidBwClTest(c client, conn *snet.Conn, messagePayload []byte,
	recBuff []byte, trips []*libcol.FullTrip, resID reservation.ID) {

	s := &colpath.ColibriPathMinimal{}
	err := s.DecodeFromBytes(c.Remote.Path.(path.Colibri).Raw)
	if err != nil {
		integration.LogFatal("DecodeFromBytes", "err", err)
	}
	s.InfoField.BwCls = 2
	err = s.SerializeTo(c.Remote.Path.(path.Colibri).Raw)
	if err != nil {
		integration.LogFatal("SerializeTo", "err", err)
	}
	_, err = conn.WriteTo(messagePayload, c.Remote)
	if err != nil {
		integration.LogFatal("writing data with colibri", "err", err)
	}
	conn.SetReadDeadline(time.Now().Add(c.Timeout))
	_, _, err = conn.ReadFrom(recBuff)
	if err == nil {
		integration.LogFatal("reading data", "err", err)
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

func (c client) renewRsv(ctx context.Context, fullTrip *libcol.FullTrip,
	requestBW reservation.BWCls, resID reservation.ID, index uint8) (snet.Path, error) {

	now := time.Now()
	setupReq, err := libcol.NewReservation(ctx, c.DRKeyFetcher, fullTrip, c.Local.Host.IP,
		c.Remote.Host.IP, requestBW)
	if err != nil {
		return nil, err
	}
	setupReq.Id = resID
	setupReq.Index = reservation.IndexNumber(index)
	err = setupReq.CreateAuthenticators(ctx, c.DRKeyFetcher)
	if err != nil {
		return nil, err
	}
	res, err := c.Daemon.ColibriSetupRsv(ctx, setupReq)
	if err != nil {
		return nil, err
	}
	err = res.ValidateAuthenticators(ctx, c.DRKeyFetcher, fullTrip.PathSteps(),
		c.Local.Host.IP, now)
	if err != nil {
		return nil, err
	}
	if string(resID.Suffix) != string(setupReq.Id.Suffix) {
		return nil, serrors.New("New id was created instead of using existing one")
	}
	return res.ColibriPath, nil
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
	err = res.ValidateAuthenticators(ctx, c.DRKeyFetcher, fullTrip.PathSteps(),
		c.Local.Host.IP, now)
	if err != nil {
		return reservation.ID{}, nil, err
	}
	return setupReq.Id, res.ColibriPath, nil
}
