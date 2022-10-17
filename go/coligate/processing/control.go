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

package processing

import (
	"hash/fnv"
	"math/rand"
	"net"
	"syscall"
	"time"

	"github.com/scionproto/scion/go/coligate/reservation"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/coligate/config"
	cggrpc "github.com/scionproto/scion/go/pkg/coligate/grpc"
	cgpb "github.com/scionproto/scion/go/pkg/proto/coligate"
	"golang.org/x/net/ipv4"
	"google.golang.org/grpc"
)

type control struct {
	channels            []chan *coligatePacketProcessor
	reservationChannels []chan *reservation.ReservationTask
	cleanupChannel      chan *reservation.ReservationTask
	egressMapping       map[uint16]*net.UDPAddr
	salt                string
}

var bufSize int = 9000 //TODO check size

// Initializes the colibri gateway. Configures the channels, goroutines, the control plane and the data plane
func Init(config *config.ColigateConfig, cleanup *app.Cleanup, egressMapping *map[uint16]*net.UDPAddr, serverAddr *snet.UDPAddr) error {
	control := control{}
	//loads the salt for load balancing from the config. If the salt is empty a random value will be chosen
	if config.Salt == "" {
		randomSalt := make([]byte, 16)
		rand.Read(randomSalt)
		control.salt = string(randomSalt)
	} else {
		control.salt = config.Salt
	}

	//creates all the channels and starts the go routines
	control.cleanupChannel = make(chan *reservation.ReservationTask, 1000) //TODO check channel capacity
	control.channels = make([]chan *coligatePacketProcessor, config.NumWorkers)
	control.reservationChannels = make([]chan *reservation.ReservationTask, config.NumWorkers)
	for i := 0; i < config.NumWorkers; i++ {
		control.channels[i] = make(chan *coligatePacketProcessor, config.MaxQueueSizePerThread)
		control.reservationChannels[i] = make(chan *reservation.ReservationTask, config.MaxQueueSizePerThread)
		go func(i int) {
			defer log.HandlePanic()
			control.threadReceiveEntry(control.channels[i], control.reservationChannels[i], config, uint32(i), uint32(config.ColibriGatewayID))
		}(i)
	}

	err := control.initCleanupRoutine()
	if err != nil {
		return err
	}
	err = control.initControlPlane(config, cleanup, serverAddr)
	if err != nil {
		return err
	}
	err = control.initDataPlane(config, egressMapping)
	if err != nil {
		return err
	}
	return nil
}

// initializes the cleanup routine that removes outdated reservations
func (control *control) initCleanupRoutine() error {
	go func() {
		defer log.HandlePanic()
		data := make(map[string]time.Time)
		for {
			for resId, val := range data {
				select {
				case task := <-control.cleanupChannel:
					data[task.ResId] = task.Reservation.Validity
				default:
					if time.Until(val) < 0 {
						deletionTask := &reservation.ReservationTask{}
						deletionTask.IsDeleteQuery = true
						deletionTask.ResId = resId
						control.reservationChannels[hash(resId, control.salt)] <- deletionTask
						delete(data, resId)
					}
				}
			}
		}
	}()
	return nil
}

// The function to initialize the control plane of the colibri gateway.
func (control *control) initControlPlane(config *config.ColigateConfig, cleanup *app.Cleanup, serverAddr *snet.UDPAddr) error {
	lis, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   serverAddr.Host.IP,
		Port: serverAddr.Host.Port,
		Zone: serverAddr.Host.Zone,
	})
	if err != nil {
		return err
	}
	s := grpc.NewServer()
	coligate := &cggrpc.Coligate{
		Salt:                control.salt,
		ReservationChannels: control.reservationChannels,
		CleanupChannel:      control.cleanupChannel,
	}
	cgpb.RegisterColibriGatewayServer(s, coligate)
	go func() {
		defer log.HandlePanic()
		s.Serve(lis)
	}()
	cleanup.Add(func() error { s.GracefulStop(); return nil })
	return nil
}

// The function to initialize the data plane of the colibri gateway.
func (control *control) initDataPlane(config *config.ColigateConfig, egressMapping *map[uint16]*net.UDPAddr) error {
	//creates the channels and goroutines that

	udpAddr, err := net.ResolveUDPAddr("udp", ":30042") //TODO check port
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	defer udpConn.Close()

	msgs := make([]ipv4.Message, 10)
	for i := 0; i < 10; i++ {
		msgs[i].Buffers = [][]byte{make([]byte, bufSize)} //TODO check buffer size
	}

	var ipv4Conn *ipv4.PacketConn = ipv4.NewPacketConn(udpConn)

	for {
		numPkts, err := ipv4Conn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
		if err != nil {
			//do something
			continue
		}
		if numPkts == 0 {
			continue
		}
		for _, p := range msgs[:numPkts] {
			var proc *coligatePacketProcessor
			proc, err = Parse(p.Buffers[0][:p.N])
			if err != nil {
				continue
			}
			var selectedChannel uint32 = hash(string(proc.colibriPath.InfoField.ResIdSuffix), control.salt) % uint32(config.NumWorkers)
			select {
			case control.channels[selectedChannel] <- proc:
			default:
				continue //packet dropped
			}
		}

	}
}

// Internal method to get the address of the corresponding border router
// to forward the outgoing packets
func (c *control) getBorderRouterAddress(proc *coligatePacketProcessor) (*net.UDPAddr, error) {
	var egressId uint16 = proc.colibriPath.GetCurrentHopField().EgressId
	addr, found := c.egressMapping[egressId]
	if !found {
		return nil, serrors.New("egress interface is invalid:", "egressId", egressId)
	}
	return addr, nil
}

// Internal method to calculate the hash value of a input string with a
// salt value. It uses the fnv-1a algorithm.
func hash(s string, salt string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s + salt))
	return h.Sum32()
}

// configures a goroutine to listen for the data plane channel and reservation updates
func (c *control) threadReceiveEntry(ch chan *coligatePacketProcessor, chres chan *reservation.ReservationTask,
	config *config.ColigateConfig, workerId uint32, gatewayId uint32) {

	worker := Worker{}
	worker.InitWorker(config, workerId, gatewayId)

	writeMsgs := make([]ipv4.Message, 1)
	writeMsgs[0].Buffers = [][]byte{make([]byte, bufSize)} //TODO check capacity

	for {
		select {
		case proc := <-ch: //data plane packet received
			addr, err := c.getBorderRouterAddress(proc)
			if err != nil {
				continue
			}
			conn, _ := net.DialUDP("udp", nil, addr)
			var borderRouterConn *ipv4.PacketConn = ipv4.NewPacketConn(conn)
			worker.ColigatePacketProcessor = proc
			err = worker.process()
			if err != nil {
				continue
			}

			writeMsgs[0].Buffers[0] = worker.ColigatePacketProcessor.rawPacket
			writeMsgs[0].Addr = addr

			borderRouterConn.WriteBatch(writeMsgs, syscall.MSG_DONTWAIT)
		case proc := <-chres: //reservation update received
			worker.handleReservationTask(proc)
		}

	}
}
