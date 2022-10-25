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
	"context"
	"hash/fnv"
	"math/rand"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/scionproto/scion/go/coligate/reservation"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/coligate/config"
	cggrpc "github.com/scionproto/scion/go/pkg/coligate/grpc"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	copb "github.com/scionproto/scion/go/pkg/proto/colibri"
	cgpb "github.com/scionproto/scion/go/pkg/proto/coligate"
	"golang.org/x/net/ipv4"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

type control struct {
	channels            []chan *coligatePacketProcessor
	reservationChannels []chan *reservation.ReservationTask
	cleanupChannel      chan *reservation.ReservationTask
	egressMapping       map[uint16]*net.UDPAddr
	salt                string
	exit                bool
}

var bufSize int = 9000 //TODO check size

// Initializes the colibri gateway. Configures the channels, goroutines, the control plane and the data plane
func Init(ctx context.Context, config *config.ColigateConfig, cleanup *app.Cleanup, egressMapping *map[uint16]*net.UDPAddr,
	serverAddr *snet.UDPAddr, colibiServiceAddr *net.UDPAddr, g *errgroup.Group) error {

	control := control{}

	cleanup.Add(func() error {
		control.exit = true
		return nil
	})

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
		func(i int) {
			g.Go(func() error {
				defer log.HandlePanic()
				return control.threadReceiveEntry(control.channels[i], control.reservationChannels[i], config, uint32(i), uint32(config.ColibriGatewayID))
			})
		}(i)
	}

	control.initCleanupRoutine(g)
	err := control.initControlPlane(config, cleanup, serverAddr, g)
	if err != nil {
		return err
	}
	control.loadActiveReservationsFromColibriService(ctx, colibiServiceAddr, g)
	err = control.initDataPlane(config, egressMapping, g)
	if err != nil {
		return err
	}

	return nil
}

// Loads the active EE Reservations from the colibri service
func (control *control) loadActiveReservationsFromColibriService(ctx context.Context, colibiServiceAddr *net.UDPAddr, g *errgroup.Group) {
	g.Go(func() error {
		defer log.HandlePanic()
		log.Info("load active reservations from colibri service")
		var grpcconn *grpc.ClientConn
		var err error
		var copbservice copb.ColibriServiceClient
		var response *copb.ActiveIndicesResponse
		success := false
		for !success {
			time.Sleep(1 * time.Second)
			grpcconn, err = grpc.Dial(colibiServiceAddr.String(), grpc.WithInsecure()) //TODO add transport security
			if err != nil {
				log.Debug("Error while loading reservation indices from colibri service. Retrying...", "error", err.Error())
				continue
			}
			copbservice = copb.NewColibriServiceClient(grpcconn)
			response, err = copbservice.ActiveIndices(ctx, &copb.ActiveIndicesRequest{})
			if err != nil {
				log.Debug("Error while loading reservation indices from colibri service. Retrying...", "error", err.Error())
				continue
			}
			success = true
		}

		for _, respReservation := range response.Reservations {
			highestValidity := time.Unix(0, 0)
			res := &reservation.Reservation{
				ReservationId: strconv.FormatInt(int64(respReservation.Id.Asid), 10) + string(respReservation.Id.Suffix),
				Rlc:           0, //TODO
				Indices:       make(map[uint8]*reservation.ReservationIndex),
				Hops: []reservation.HopField{ //TODO add other hop fields too
					{
						EgressId: uint16(respReservation.Egress),
					},
				},
			}
			for _, respReservationVersion := range respReservation.Indices {
				resver := &reservation.ReservationIndex{
					Version:  uint8(respReservationVersion.Index),
					Validity: util.SecsToTime(respReservationVersion.ExpirationTime),
					BwCls:    uint8(respReservationVersion.AllocBw),
					Macs:     respReservationVersion.Sigmas,
				}
				res.Indices[uint8(respReservationVersion.Index)] = resver
				if resver.Validity.Sub(highestValidity) > 0 {
					highestValidity = resver.Validity
				}
			}
			task := &reservation.ReservationTask{
				ResId:           res.ReservationId,
				Reservation:     res,
				HighestValidity: highestValidity,
			}
			control.cleanupChannel <- task
			control.reservationChannels[hash(task.ResId, control.salt)] <- task
		}
		log.Info("Successfully loaded reservations from colibri service")
		return nil
	})

}

// initializes the cleanup routine that removes outdated reservations
func (control *control) initCleanupRoutine(g *errgroup.Group) {
	g.Go(func() error {
		defer log.HandlePanic()
		log.Info("Init cleanup routine")
		data := make(map[string]time.Time)
		for !control.exit {
			for resId, val := range data {
				select {
				case task := <-control.cleanupChannel:
					res, exists := data[task.ResId]
					if exists {
						if task.HighestValidity.Sub(res) > 0 {
							data[task.ResId] = task.HighestValidity
						}
					} else {
						data[task.ResId] = task.HighestValidity
					}
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
			time.Sleep(100 * time.Millisecond)
		}
		return nil
	})
}

// The function to initialize the control plane of the colibri gateway.
func (control *control) initControlPlane(config *config.ColigateConfig, cleanup *app.Cleanup, serverAddr *snet.UDPAddr, g *errgroup.Group) error {
	log.Info("Init control plane")
	lis, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   serverAddr.Host.IP,
		Port: serverAddr.Host.Port,
		Zone: serverAddr.Host.Zone,
	})
	if err != nil {
		return err
	}

	s := grpc.NewServer(libgrpc.UnaryServerInterceptor())
	coligate := &cggrpc.Coligate{
		Salt:                control.salt,
		ReservationChannels: control.reservationChannels,
		CleanupChannel:      control.cleanupChannel,
	}
	cgpb.RegisterColibriGatewayServer(s, coligate)
	g.Go(func() error {
		defer log.HandlePanic()
		return s.Serve(lis)
	})
	cleanup.Add(func() error { s.GracefulStop(); return nil })
	return nil
}

// The function to initialize the data plane of the colibri gateway.
func (control *control) initDataPlane(config *config.ColigateConfig, egressMapping *map[uint16]*net.UDPAddr, g *errgroup.Group) error {
	//creates the channels and goroutines that
	log.Info("Init data plane")
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
	g.Go(func() error {
		defer log.HandlePanic()

		for !control.exit {
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
		return nil
	})
	return nil
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
	config *config.ColigateConfig, workerId uint32, gatewayId uint32) error {
	log.Info("Init worker", "workerId", workerId)
	worker := Worker{}
	worker.InitWorker(config, workerId, gatewayId)

	writeMsgs := make([]ipv4.Message, 1)
	writeMsgs[0].Buffers = [][]byte{make([]byte, bufSize)} //TODO check capacity

	for !c.exit {
		select {
		case proc := <-ch: //data plane packet received
			log.Debug("Worker received data packet", "workerId", workerId, "resId", string(proc.colibriPath.InfoField.ResIdSuffix))
			addr, err := c.getBorderRouterAddress(proc)
			if err != nil {
				continue
			}
			conn, _ := net.DialUDP("udp", nil, addr)
			var borderRouterConn *ipv4.PacketConn = ipv4.NewPacketConn(conn)
			worker.ColigatePacketProcessor = proc
			err = worker.process()
			if err != nil {
				log.Debug("Worker received error while processing.", "workerId", workerId, "error", err.Error())
				continue
			}

			writeMsgs[0].Buffers[0] = worker.ColigatePacketProcessor.rawPacket
			writeMsgs[0].Addr = addr

			borderRouterConn.WriteBatch(writeMsgs, syscall.MSG_DONTWAIT)
		case task := <-chres: //reservation update received
			log.Debug("Worker received reservation update", "workerId", workerId, "resId", task.ResId)
			worker.handleReservationTask(task)
		}

	}
	return nil
}
