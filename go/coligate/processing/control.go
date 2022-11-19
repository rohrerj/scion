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
	"math/rand"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/scionproto/scion/go/coligate/reservation"
	libaddr "github.com/scionproto/scion/go/lib/addr"
	libtypes "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/log"
	libmetrics "github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/app"
	common "github.com/scionproto/scion/go/pkg/coligate"
	"github.com/scionproto/scion/go/pkg/coligate/config"
	cggrpc "github.com/scionproto/scion/go/pkg/coligate/grpc"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	copb "github.com/scionproto/scion/go/pkg/proto/colibri"
	cgpb "github.com/scionproto/scion/go/pkg/proto/coligate"
)

// TODO(rohrerj) Add Unit tests

type Control struct {
	dataChannels    []chan *dataPacket
	controlChannels []chan *reservation.ReservationTask
	cleanupChannel  chan *reservation.ReservationTask
	borderRouters   map[uint16]*ipv4.PacketConn
	saltHasher      common.SaltHasher
	exit            bool
}

const bufSize int = 9000

func (c *Control) shutdown() {
	if c.exit {
		return
	}
	c.exit = true
	c.cleanupChannel <- nil
	for i := 0; i < len(c.dataChannels); i++ {
		c.dataChannels[i] <- nil
	}
	for i := 0; i < len(c.controlChannels); i++ {
		c.controlChannels[i] <- nil
	}
}

// Init initializes the colibri gateway. Configures the channels, goroutines,
// and the control plane and the data plane.
func Init(ctx context.Context, cfg *config.Config, cleanup *app.Cleanup,
	g *errgroup.Group, topo *topology.Loader, metrics *common.Metrics) error {

	config := &cfg.Coligate
	var borderRouters map[uint16]*ipv4.PacketConn = make(map[uint16]*ipv4.PacketConn)
	for ifid, info := range topo.InterfaceInfoMap() {
		conn, _ := net.DialUDP("udp", nil, info.InternalAddr)
		borderRouters[uint16(ifid)] = ipv4.NewPacketConn(conn)
		log.Debug("Found Border Router", "ifid", ifid, "internal_addr", info.InternalAddr)
	}

	coligateAddr, err := topo.ColibriGatewayAddress(cfg.General.ID)
	if err != nil {
		return err
	}

	grpcAddr, err := net.ResolveTCPAddr("tcp", cfg.Coligate.ColigateGRPCAddr)
	if err != nil {
		return err
	}

	colibriServiceAddresses := topo.ColibriServiceAddresses()
	if len(colibriServiceAddresses) < 1 {
		return serrors.New("No instance of colibri service found in local AS.")
	}

	// Loads the salt for load balancing from the config.
	// If the salt is empty a random value will be chosen
	salt := []byte(config.Salt)
	if config.Salt == "" {
		salt := make([]byte, 16)
		rand.Read(salt)
	}

	control := Control{
		borderRouters:   borderRouters,
		cleanupChannel:  make(chan *reservation.ReservationTask, 1000), //TODO(rohrerj) check channel capacity
		dataChannels:    make([]chan *dataPacket, config.NumWorkers),
		controlChannels: make([]chan *reservation.ReservationTask, config.NumWorkers),
		saltHasher:      common.NewFnv1aHasher(salt),
	}

	cleanup.Add(func() error {
		control.shutdown()
		return nil
	})

	//Creates all the channels and starts the go routines
	for i := 0; i < config.NumWorkers; i++ {
		control.dataChannels[i] = make(chan *dataPacket, config.MaxQueueSizePerWorker)
		control.controlChannels[i] = make(chan *reservation.ReservationTask,
			config.MaxQueueSizePerWorker)
		func(i int) {
			g.Go(func() error {
				defer log.HandlePanic()
				return control.workerReceiveEntry(control.dataChannels[i],
					control.controlChannels[i], config,
					uint32(i), uint32(config.ColibriGatewayID), metrics,
				)
			})
		}(i)
	}

	g.Go(func() error {
		defer log.HandlePanic()
		control.initCleanupRoutine(metrics)
		return nil
	})

	g.Go(func() error {
		defer log.HandlePanic()
		return control.initControlPlane(config, cleanup, grpcAddr, metrics)
	})

	// we start the data plane as soon as we retrieved the active reservations from colibri service
	if err := control.loadActiveReservationsFromColibriService(ctx, config, colibriServiceAddresses[0],
		config.COSyncTimeout, metrics); err != nil {
		return err
	}
	if err := control.initDataPlane(config, coligateAddr, g, cleanup, metrics); err != nil {
		return err
	}

	return nil
}

// Loads the active EE Reservations from the colibri service
func (control *Control) loadActiveReservationsFromColibriService(ctx context.Context,
	config *config.ColigateConfig, colibiServiceAddr *net.UDPAddr, timeout int, metrics *common.Metrics) error {

	log.Info("Loading active reservation indices from colibri service")
	var grpcconn *grpc.ClientConn
	var err error
	var copbservice copb.ColibriServiceClient
	var response *copb.ActiveIndicesResponse
	loadActiveReservationsTotalPromCounter := libmetrics.NewPromCounter(metrics.LoadActiveReservationsTotal)
	success := false
	timeoutTime := time.Now().Add(time.Duration(timeout) * time.Second)
	for !success {
		if time.Until(timeoutTime) < 0 {
			return serrors.New(
				"Loading active reservation indices from colibri service failed after timeout")
		}
		grpcconn, err = grpc.Dial(colibiServiceAddr.String(), grpc.WithInsecure()) //TODO(rohrerj) add transport security
		if err != nil {
			continue
		}
		copbservice = copb.NewColibriServiceClient(grpcconn)
		response, err = copbservice.ActiveIndices(ctx, &copb.ActiveIndicesRequest{})
		if err != nil {
			continue
		}
		success = true
	}
	loadActiveReservationsTotalPromCounter.Add(float64(len(response.Reservations)))
	for _, respReservation := range response.Reservations {
		highestValidity := time.Unix(0, 0)
		id, err := libtypes.NewID(libaddr.AS(respReservation.Id.Asid), respReservation.Id.Suffix)
		if err != nil {
			log.Debug("error parsing reservation id", "err", err)
			continue
		}
		res := &reservation.Reservation{
			ReservationId: string(id.ToRaw()),
			Rlc:           0, //TODO(rohrerj)
			Indices:       make(map[uint8]*reservation.ReservationIndex),
			Hops: []reservation.HopField{ //TODO(rohrerj) add other hop fields too
				{
					EgressId: uint16(respReservation.Egress),
				},
			},
		}
		for _, respReservationVersion := range respReservation.Indices {
			resver := &reservation.ReservationIndex{
				Index:    uint8(respReservationVersion.Index),
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
			ResId:             res.ReservationId,
			Reservation:       res,
			HighestValidity:   highestValidity,
			IsInitReservation: true,
		}

		control.cleanupChannel <- task

		control.controlChannels[control.saltHasher.Hash([]byte(task.ResId))%uint32(config.NumWorkers)] <- task
	}
	log.Info("Successfully loaded active reservation indices from colibri service")
	return nil
}

// initializes the cleanup routine that removes outdated reservations
func (control *Control) initCleanupRoutine(metrics *common.Metrics) {
	log.Info("Init cleanup routine")

	cleanupReservationUpdateTotalPromCounter := libmetrics.NewPromCounter(metrics.CleanupReservationUpdateTotal)
	cleanupReservationUpdateNewPromCounter := libmetrics.NewPromCounter(metrics.CleanupReservationUpdateNew)
	cleanupReservationDeletedPromCounter := libmetrics.NewPromCounter(metrics.CleanupReservationDeleted)

	data := make(map[string]time.Time)
	numWorkers := len(control.controlChannels)

	handleTask := (func(task *reservation.ReservationTask) {
		cleanupReservationUpdateTotalPromCounter.Add(1)
		res, exists := data[task.ResId]
		if !exists || task.HighestValidity.Sub(res) > 0 {
			cleanupReservationUpdateNewPromCounter.Add(1)
			data[task.ResId] = task.HighestValidity
		}
	})
	numIterations := 0
	for !control.exit { //TODO(rohrerj) check CPU usage
		if len(data) == 0 {
			task := <-control.cleanupChannel
			if task == nil {
				return
			}
			handleTask(task)
		}
		for resId, val := range data {
			if numIterations == 0 {
				select {
				case task := <-control.cleanupChannel:
					if task == nil {
						return
					}
					handleTask(task)
					if task.IsInitReservation {
						// faster progress when loading a huge amount of reservations on startup
						continue
					}
					if task.ResId == resId {
						val = data[resId] // updated current value in case it got changed
					}
					// for every new reservation check at least 10 current reservations:
					numIterations = 10
				default:
					// if no new reservation is available check
					// at least 100 current reservations:
					numIterations = 100
				}
			}
			if time.Until(val) < 0 {
				deletionTask := &reservation.ReservationTask{
					IsDeleteQuery:   true,
					ResId:           resId,
					HighestValidity: val,
				}
				cleanupReservationDeletedPromCounter.Add(1)

				control.controlChannels[control.saltHasher.
					Hash([]byte(resId))%uint32(numWorkers)] <- deletionTask
				delete(data, resId)
			}
			numIterations--
		}
	}
}

// The function to initialize the control plane of the colibri gateway.
func (control *Control) initControlPlane(config *config.ColigateConfig, cleanup *app.Cleanup,
	serverAddr *net.TCPAddr, metrics *common.Metrics) error {

	log.Info("Init control plane")
	lis, err := net.ListenTCP("tcp", serverAddr)
	if err != nil {
		return err
	}

	s := grpc.NewServer(libgrpc.UnaryServerInterceptor())
	coligate := &cggrpc.Coligate{
		Hasher:                       control.saltHasher,
		ReservationChannels:          control.controlChannels,
		CleanupChannel:               control.cleanupChannel,
		UpdateSigmasTotalPromCounter: libmetrics.NewPromCounter(metrics.UpdateSigmasTotal),
	}
	cgpb.RegisterColibriGatewayServer(s, coligate)
	cleanup.Add(func() error { s.GracefulStop(); return nil })

	return s.Serve(lis)
}

// The function to initialize the data plane of the colibri gateway.
func (control *Control) initDataPlane(config *config.ColigateConfig, gatewayAddr *net.UDPAddr,
	g *errgroup.Group, cleanup *app.Cleanup, metrics *common.Metrics) error {

	log.Info("Init data plane")
	udpConn, err := net.ListenUDP("udp", gatewayAddr)
	if err != nil {
		return err
	}
	cleanup.Add(func() error { udpConn.Close(); return nil })
	msgs := make([]ipv4.Message, 10) //TODO(rohrerj) check msg size
	for i := 0; i < 10; i++ {
		msgs[i].Buffers = [][]byte{make([]byte, bufSize)}
	}

	var ipv4Conn *ipv4.PacketConn = ipv4.NewPacketConn(udpConn)

	g.Go(func() error {
		defer log.HandlePanic()
		dataPacketInTotalPromCounter := libmetrics.NewPromCounter(metrics.DataPacketInTotal)
		dataPacketInInvalidPromCounter := libmetrics.NewPromCounter(metrics.DataPacketInInvalid)

		for !control.exit {
			numPkts, err := ipv4Conn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
			if err != nil {
				//do something
				log.Debug("error while reading from network", "err", err)
				continue
			}
			if numPkts == 0 {
				continue
			}
			log.Debug("received data packets")
			dataPacketInTotalPromCounter.Add(float64(numPkts))
			for _, p := range msgs[:numPkts] {
				var proc *dataPacket
				proc, err = Parse(p.Buffers[0][:p.N])
				if err != nil {
					log.Debug("error while parsing headers", "err", err)
					dataPacketInInvalidPromCounter.Add(1)
					continue
				}
				proc.pktArrivalTime = time.Now()
				id, err := libtypes.NewID(proc.scionLayer.SrcIA.AS(),
					proc.colibriPath.InfoField.ResIdSuffix)
				if err != nil {
					log.Debug("cannot parse reservation id")
					continue
				}
				var selectedChannel uint32 = control.saltHasher.Hash(id.ToRaw()) % uint32(config.NumWorkers)
				select {
				case control.dataChannels[selectedChannel] <- proc:
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
func (c *Control) getBorderRouterConnection(proc *dataPacket) (*ipv4.PacketConn, error) {
	var egressId uint16 = proc.colibriPath.GetCurrentHopField().EgressId
	conn, found := c.borderRouters[egressId]
	if !found {
		return nil, serrors.New("egress interface is invalid:", "egressId", egressId)
	}
	return conn, nil
}

// Configures a goroutine to listen for the data plane channel and reservation updates
func (c *Control) workerReceiveEntry(ch chan *dataPacket,
	chres chan *reservation.ReservationTask, config *config.ColigateConfig, workerId uint32,
	gatewayId uint32, metrics *common.Metrics) error {

	log.Info("Init worker", "workerId", workerId)
	worker := NewWorker(config, workerId, gatewayId)

	workerPacketInTotalPromCounter := libmetrics.NewPromCounter(metrics.WorkerPacketInTotal)
	workerPacketInInvalidPromCounter := libmetrics.NewPromCounter(metrics.WorkerPacketInInvalid)
	workerPacketOutTotalPromCounter := libmetrics.NewPromCounter(metrics.WorkerPacketOutTotal)
	workerReservationUpdateTotalPromCounter := libmetrics.NewPromCounter(metrics.WorkerReservationUpdateTotal)

	writeMsgs := make([]ipv4.Message, 1)
	writeMsgs[0].Buffers = [][]byte{make([]byte, bufSize)}

	for !c.exit {
		select {
		case proc := <-ch: //data plane packet received
			if proc == nil { //if proc is nil it is meant to be a exit sequence
				return nil
			}
			log.Debug("Worker received data packet", "workerId", workerId,
				"resId", string(proc.colibriPath.InfoField.ResIdSuffix))
			workerPacketInTotalPromCounter.Add(1)
			borderRouterConn, err := c.getBorderRouterConnection(proc)
			if err != nil {
				log.Debug("Error getting border router connection", "err", err)
				workerPacketInInvalidPromCounter.Add(1)
				continue
			}
			if err = worker.process(proc); err != nil {
				log.Debug("Worker received error while processing.", "workerId", workerId,
					"error", err.Error())
				workerPacketInInvalidPromCounter.Add(1)
				continue
			}

			writeMsgs[0].Buffers[0] = proc.rawPacket
			writeMsgs[0].Addr = borderRouterConn.LocalAddr()

			borderRouterConn.WriteBatch(writeMsgs, syscall.MSG_DONTWAIT)
			workerPacketOutTotalPromCounter.Add(1)
			log.Debug("Worker forwarded packet", "workerId", workerId,
				"border router", borderRouterConn.LocalAddr().String())
		case task := <-chres: //reservation update received
			if task == nil {
				return nil
			}
			log.Debug("Worker received reservation update", "workerId", workerId,
				"resId", task.ResId)
			workerReservationUpdateTotalPromCounter.Add(1)
			worker.handleReservationTask(task)
		}

	}
	return nil
}
