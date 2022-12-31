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

	"github.com/scionproto/scion/go/coligate/storage"
	libaddr "github.com/scionproto/scion/go/lib/addr"
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

type Processor struct {
	localIA                 libaddr.IA
	dataChannels            []chan *dataPacket
	controlUpdateChannels   []chan *storage.UpdateTask
	controlDeletionChannels []chan *storage.DeletionTask
	cleanupChannel          chan *storage.UpdateTask
	borderRouters           map[uint16]*ipv4.PacketConn
	saltHasher              common.SaltHasher
	exit                    bool
	metrics                 *ColigateMetrics
	numWorkers              int
}

// BufSize is the maximum size of a datapacket including all the headers.
const bufSize int = 9000

// NumOfMessages is the maximum number of messages that are read as a batch from the socket.
const numOfMessages int = 10 // TODO(rohrerj) check msg size

func (c *Processor) shutdown() {
	if c.exit {
		return
	}
	c.exit = true
	c.cleanupChannel <- nil
	for i := 0; i < len(c.dataChannels); i++ {
		c.dataChannels[i] <- nil
	}
	for i := 0; i < len(c.controlUpdateChannels); i++ {
		c.controlUpdateChannels[i] <- nil
	}
	for i := 0; i < len(c.controlDeletionChannels); i++ {
		c.controlDeletionChannels[i] <- nil
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
	}
	coligateInfo, err := topo.ColibriGateway(cfg.General.ID)
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

	localAS := topo.IA().AS()

	// Loads the salt for load balancing from the config.
	// If the salt is empty a random value will be chosen
	salt := []byte(config.Salt)
	if config.Salt == "" {
		salt := make([]byte, 16)
		rand.Read(salt)
	}

	p := Processor{
		localIA: topo.IA(),
		// TODO(rohrerj) check cleanupChannel capacity
		cleanupChannel:          make(chan *storage.UpdateTask, 1000),
		dataChannels:            make([]chan *dataPacket, config.NumWorkers),
		controlUpdateChannels:   make([]chan *storage.UpdateTask, config.NumWorkers),
		controlDeletionChannels: make([]chan *storage.DeletionTask, config.NumWorkers),
		saltHasher:              common.NewFnv1aHasher(salt),
		metrics:                 initializeMetrics(metrics),
		numWorkers:              config.NumWorkers,
		borderRouters:           borderRouters,
	}

	cleanup.Add(func() error {
		p.shutdown()
		return nil
	})

	// Creates all the channels and starts the go routines
	for i := 0; i < p.numWorkers; i++ {
		p.dataChannels[i] = make(chan *dataPacket, config.MaxQueueSizePerWorker)
		p.controlUpdateChannels[i] = make(chan *storage.UpdateTask,
			config.MaxQueueSizePerWorker)
		// TODO(rohrerj) Check control deletion channel size
		p.controlDeletionChannels[i] = make(chan *storage.DeletionTask, 1000)
		func(i int) {
			g.Go(func() error {
				defer log.HandlePanic()
				return p.workerReceiveEntry(config,
					uint32(i), uint32(config.ColibriGatewayID), localAS,
				)
			})
		}(i)
	}

	g.Go(func() error {
		defer log.HandlePanic()
		p.initCleanupRoutine()
		return nil
	})

	g.Go(func() error {
		defer log.HandlePanic()
		return p.initControlPlane(config, cleanup, grpcAddr)
	})

	// We start the data plane as soon as we retrieved the active reservations from colibri service
	if err := p.loadActiveReservationsFromColibriService(ctx, config, colibriServiceAddresses[0],
		config.COSyncTimeout, cfg.General.ID); err != nil {
		return err
	}
	for i := 0; i < 255; i++ {
		for j := 0; j < 255; j++ {
			resId := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i), byte(j)}
			res := storage.NewReservation(resId, []storage.HopField{
				{
					IngressId: 0,
					EgressId:  1,
				},
				{
					IngressId: 1,
					EgressId:  2,
				},
			})
			index := storage.NewIndex(0, time.Date(2030, 1, 1, 0, 0, 0, 0, time.Local), 50, [][]byte{
				{},
				{},
			})
			res.Indices = map[uint8]*storage.ReservationIndex{
				0: index,
			}
			task := storage.NewUpdateTask(res, time.Date(2030, 1, 1, 0, 0, 0, 0, time.Local))
			p.controlUpdateChannels[p.getWorkerForResId(resId)] <- task
		}
	}
	if err := p.initDataPlane(config, coligateInfo.Addr, g, cleanup); err != nil {
		return err
	}

	return nil
}

type ColigateMetrics struct {
	LoadActiveReservationsTotal   libmetrics.Counter
	CleanupReservationUpdateTotal libmetrics.Counter
	CleanupReservationUpdateNew   libmetrics.Counter
	CleanupReservationDeleted     libmetrics.Counter
	UpdateSigmasTotal             libmetrics.Counter
	DataPacketInTotal             libmetrics.Counter
	DataPacketInInvalid           libmetrics.Counter
	DataPacketInDropped           libmetrics.Counter
	WorkerPacketInTotal           libmetrics.Counter
	WorkerPacketInInvalid         libmetrics.Counter
	WorkerPacketOutTotal          libmetrics.Counter
	WorkerPacketOutError          libmetrics.Counter
	WorkerReservationUpdateTotal  libmetrics.Counter
}

func initializeMetrics(metrics *common.Metrics) *ColigateMetrics {
	c := &ColigateMetrics{
		LoadActiveReservationsTotal: libmetrics.NewPromCounter(
			metrics.LoadActiveReservationsTotal),
		CleanupReservationUpdateTotal: libmetrics.NewPromCounter(
			metrics.CleanupReservationUpdateTotal),
		CleanupReservationUpdateNew: libmetrics.NewPromCounter(
			metrics.CleanupReservationUpdateNew),
		CleanupReservationDeleted: libmetrics.NewPromCounter(
			metrics.CleanupReservationDeleted),
		UpdateSigmasTotal: libmetrics.NewPromCounter(
			metrics.UpdateSigmasTotal),
		DataPacketInTotal: libmetrics.NewPromCounter(
			metrics.DataPacketInTotal),
		DataPacketInInvalid: libmetrics.NewPromCounter(
			metrics.DataPacketInInvalid),
		DataPacketInDropped: libmetrics.NewPromCounter(
			metrics.DataPacketInDropped),
		WorkerPacketInTotal: libmetrics.NewPromCounter(
			metrics.WorkerPacketInTotal),
		WorkerPacketInInvalid: libmetrics.NewPromCounter(
			metrics.WorkerPacketInInvalid),
		WorkerPacketOutTotal: libmetrics.NewPromCounter(
			metrics.WorkerPacketOutTotal),
		WorkerPacketOutError: libmetrics.NewPromCounter(
			metrics.WorkerPacketOutError),
		WorkerReservationUpdateTotal: libmetrics.NewPromCounter(
			metrics.WorkerReservationUpdateTotal),
	}
	return c
}

// Loads the active EE Reservations from the colibri service
func (p *Processor) loadActiveReservationsFromColibriService(ctx context.Context,
	config *config.ColigateConfig, colibiServiceAddr *net.UDPAddr, timeout int, coligateId string) error {

	log.Info("Loading active reservation indices from colibri service")
	var response *copb.ActiveIndicesResponse
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		if time.Now().After(deadline) {
			return serrors.New(
				"Loading active reservation indices from colibri service failed after timeout")
		}
		// TODO(rohrerj) Add security for connection with colibri service.
		grpcconn, err := grpc.Dial(colibiServiceAddr.String(), grpc.WithInsecure())
		if err != nil {
			continue
		}
		copbservice := copb.NewColibriServiceClient(grpcconn)
		response, err = copbservice.ActiveIndices(ctx, &copb.ActiveIndicesRequest{
			ColigateId: coligateId,
		})
		if err != nil {
			continue
		}
		break
	}
	p.metrics.LoadActiveReservationsTotal.Add(float64(len(response.Reservations)))
	for _, respReservation := range response.Reservations {
		highestValidity := time.Unix(0, 0)
		newId := [12]byte{}
		copy(newId[:], respReservation.Id.Suffix)

		res := storage.NewReservation(newId,
			[]storage.HopField{
				{
					EgressId: uint16(respReservation.Egress),
				},
			})
		for _, respResIndex := range respReservation.Indices {
			resIndex := storage.NewIndex(uint8(respResIndex.Index),
				util.SecsToTime(respResIndex.ExpirationTime),
				uint8(respResIndex.AllocBw), respResIndex.Sigmas)

			res.Indices[resIndex.Index] = resIndex
			if resIndex.Validity.Sub(highestValidity) > 0 {
				highestValidity = resIndex.Validity
			}
		}
		task := storage.NewUpdateTask(res, highestValidity)

		// Registers the reservation for deletion once it expires
		p.cleanupChannel <- task

		p.controlUpdateChannels[p.getWorkerForResId(task.Reservation.Id)] <- task
	}
	log.Info("Successfully loaded active reservation indices from colibri service")
	return nil
}

func (p *Processor) getWorkerForResId(resId [12]byte) uint32 {
	return p.saltHasher.Hash(resId[:]) % uint32(p.numWorkers)
}

// Initializes the cleanup routine that removes outdated reservations
func (p *Processor) initCleanupRoutine() {
	log.Info("Init cleanup routine")

	reservationExpirations := make(map[[12]byte]time.Time)

	updateExpirationMapping := (func(task *storage.UpdateTask) {
		p.metrics.CleanupReservationUpdateTotal.Add(1)
		res, exists := reservationExpirations[task.Reservation.Id]
		if !exists || task.HighestValidity.After(res) {
			p.metrics.CleanupReservationUpdateNew.Add(1)
			reservationExpirations[task.Reservation.Id] = task.HighestValidity
		}
	})
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	for !p.exit {
		select {
		case task := <-p.cleanupChannel:
			if task == nil {
				return
			}
			updateExpirationMapping(task)
		case now := <-t.C:
			updateTime := false
			for resId, val := range reservationExpirations {
			out:
				for {
					select {
					case task := <-p.cleanupChannel:
						if task == nil {
							return
						}
						updateExpirationMapping(task)
						if task.Reservation.Id == resId {
							// Updated current value in case it got changed
							val = reservationExpirations[resId]
						}
						updateTime = true
					default:
						if updateTime {
							now = time.Now()
							updateTime = false
						}
						break out
					}
				}
				if val.Before(now) {
					p.metrics.CleanupReservationDeleted.Add(1)

					workerId := p.getWorkerForResId(resId)
					p.controlDeletionChannels[workerId] <- storage.NewDeletionTask(resId)
					delete(reservationExpirations, resId)
				}
			}
		}
	}
}

// The function to initialize the control plane of the colibri gateway.
func (p *Processor) initControlPlane(config *config.ColigateConfig, cleanup *app.Cleanup,
	serverAddr *net.TCPAddr) error {

	log.Info("Init control plane", "addr", serverAddr)
	lis, err := net.ListenTCP("tcp", serverAddr)
	if err != nil {
		return err
	}

	s := grpc.NewServer(libgrpc.UnaryServerInterceptor())
	coligate := &cggrpc.Coligate{
		LocalIA:                      p.localIA,
		ReservationChannels:          p.controlUpdateChannels,
		CleanupChannel:               p.cleanupChannel,
		UpdateSigmasTotalPromCounter: p.metrics.UpdateSigmasTotal,
		FindWorker:                   p.getWorkerForResId,
	}
	cgpb.RegisterColibriGatewayServiceServer(s, coligate)
	cleanup.Add(func() error { s.GracefulStop(); return nil })

	return s.Serve(lis)
}

// The function to initialize the data plane of the colibri gateway.
func (p *Processor) initDataPlane(config *config.ColigateConfig, gatewayAddr *net.UDPAddr,
	g *errgroup.Group, cleanup *app.Cleanup) error {

	log.Info("Init data plane")
	udpConn, err := net.ListenUDP("udp", gatewayAddr)
	if err != nil {
		return err
	}
	cleanup.Add(func() error { udpConn.Close(); return nil })
	msgs := make([]ipv4.Message, numOfMessages)
	for i := 0; i < numOfMessages; i++ {
		msgs[i].Buffers = [][]byte{make([]byte, bufSize)}
	}

	var ipv4Conn *ipv4.PacketConn = ipv4.NewPacketConn(udpConn)

	g.Go(func() error {
		defer log.HandlePanic()
		dataPacketInTotalPromCounter := p.metrics.DataPacketInTotal
		dataPacketInInvalidPromCounter := p.metrics.DataPacketInInvalid
		dataPacketInDroppedPromCounter := p.metrics.DataPacketInDropped
		for !p.exit {
			numPkts, err := ipv4Conn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
			if err != nil {
				log.Debug("error while reading from network", "err", err)
				continue
			}
			if numPkts == 0 {
				continue
			}
			dataPacketInTotalPromCounter.Add(float64(numPkts))
			for _, pkt := range msgs[:numPkts] {
				var d *dataPacket

				d, err = Parse(pkt.Buffers[0][:pkt.N])
				if err != nil {
					log.Debug("error while parsing headers", "err", err)
					dataPacketInInvalidPromCounter.Add(1)
					continue
				}
				if int(d.scionLayer.PayloadLen) != len(d.scionLayer.Payload) ||
					d.scionLayer.PayloadLen != d.colibriPath.InfoField.OrigPayLen {
					// Packet too large or inconsistent payload size.
					dataPacketInInvalidPromCounter.Add(1)
					continue
				}
				d.pktArrivalTime = time.Now()

				select {
				case p.dataChannels[p.getWorkerForResId(d.id)] <- d:
				default:
					dataPacketInDroppedPromCounter.Add(1)
					continue // Packet dropped
				}
			}

		}
		return nil
	})
	return nil
}

// Configures a goroutine to listen for the data plane channel and control plane reservation updates
func (p *Processor) workerReceiveEntry(config *config.ColigateConfig, workerId uint32,
	gatewayId uint32, localAS libaddr.AS) error {

	log.Info("Init worker", "workerId", workerId)
	worker := NewWorker(config, workerId, gatewayId, localAS)

	workerPacketInTotalPromCounter := p.metrics.WorkerPacketInTotal
	workerPacketInInvalidPromCounter := p.metrics.WorkerPacketInInvalid
	workerPacketOutTotalPromCounter := p.metrics.WorkerPacketOutTotal
	workerPacketOutErrorPromCounter := p.metrics.WorkerPacketOutError
	workerReservationUpdateTotalPromCounter := p.metrics.WorkerReservationUpdateTotal

	writeMsgs := make([]ipv4.Message, 1)
	writeMsgs[0].Buffers = [][]byte{make([]byte, bufSize)} // TODO(rohrerj) Check for optimizations

	ch := p.dataChannels[workerId]
	chres := p.controlUpdateChannels[workerId]
	chresD := p.controlDeletionChannels[workerId]

	for !p.exit {
		// Check whether new reservation indices have to be processed.
		// This has priority above the data plane packets.
		select {
		case task := <-chres:
			if task == nil {
				return nil
			}
			workerReservationUpdateTotalPromCounter.Add(1)
			task.Execute(worker.Storage)
			continue
		default:
		}

		select {
		case d := <-ch: // Data plane packet received
			if d == nil { // If d is nil it is meant to be a exit sequence
				return nil
			}
			workerPacketInTotalPromCounter.Add(1)
			var egressId uint16 = d.colibriPath.GetCurrentHopField().EgressId
			borderRouterConn, found := p.borderRouters[egressId]
			if !found {
				continue
			}
			if err := worker.process(d); err != nil {
				log.Debug("Worker received error while processing.", "workerId", workerId,
					"error", err.Error())
				workerPacketInInvalidPromCounter.Add(1)
				continue
			}

			writeMsgs[0].Buffers[0] = d.rawPacket

			_, err := borderRouterConn.WriteBatch(writeMsgs, syscall.MSG_DONTWAIT)
			if err != nil {
				log.Debug("Error writing packet", "err", err)
				workerPacketOutErrorPromCounter.Add(1)
				continue
			}
			workerPacketOutTotalPromCounter.Add(1)
		case task := <-chres:
			if task == nil {
				return nil
			}
			workerReservationUpdateTotalPromCounter.Add(1)
			task.Execute(worker.Storage)
		case task := <-chresD: // Reservation deletion received.
			if task == nil {
				return nil
			}
			workerReservationUpdateTotalPromCounter.Add(1)
			task.Execute(worker.Storage)
		}

	}
	return nil
}
