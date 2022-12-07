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

	localAS := topo.IA().AS()

	// Loads the salt for load balancing from the config.
	// If the salt is empty a random value will be chosen
	salt := []byte(config.Salt)
	if config.Salt == "" {
		salt := make([]byte, 16)
		rand.Read(salt)
	}

	p := Processor{
		localIA:                 topo.IA(),
		borderRouters:           borderRouters,
		cleanupChannel:          make(chan *storage.UpdateTask, 1000), // TODO(rohrerj) check channel capacity
		dataChannels:            make([]chan *dataPacket, config.NumWorkers),
		controlUpdateChannels:   make([]chan *storage.UpdateTask, config.NumWorkers),
		controlDeletionChannels: make([]chan *storage.DeletionTask, config.NumWorkers),
		saltHasher:              common.NewFnv1aHasher(salt),
		metrics:                 initializeMetrics(metrics),
		numWorkers:              config.NumWorkers,
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
		p.controlDeletionChannels[i] = make(chan *storage.DeletionTask, 1000) //TODO(rohrerj) Check size
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
		config.COSyncTimeout); err != nil {
		return err
	}
	if err := p.initDataPlane(config, coligateAddr, g, cleanup); err != nil {
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
	WorkerPacketInTotal           libmetrics.Counter
	WorkerPacketInInvalid         libmetrics.Counter
	WorkerPacketOutTotal          libmetrics.Counter
	WorkerReservationUpdateTotal  libmetrics.Counter
}

func initializeMetrics(metrics *common.Metrics) *ColigateMetrics {
	c := &ColigateMetrics{
		LoadActiveReservationsTotal:   libmetrics.NewPromCounter(metrics.LoadActiveReservationsTotal),
		CleanupReservationUpdateTotal: libmetrics.NewPromCounter(metrics.CleanupReservationUpdateTotal),
		CleanupReservationUpdateNew:   libmetrics.NewPromCounter(metrics.CleanupReservationUpdateNew),
		CleanupReservationDeleted:     libmetrics.NewPromCounter(metrics.CleanupReservationDeleted),
		UpdateSigmasTotal:             libmetrics.NewPromCounter(metrics.UpdateSigmasTotal),
		DataPacketInTotal:             libmetrics.NewPromCounter(metrics.DataPacketInTotal),
		DataPacketInInvalid:           libmetrics.NewPromCounter(metrics.DataPacketInInvalid),
		WorkerPacketInTotal:           libmetrics.NewPromCounter(metrics.WorkerPacketInTotal),
		WorkerPacketInInvalid:         libmetrics.NewPromCounter(metrics.WorkerPacketInInvalid),
		WorkerPacketOutTotal:          libmetrics.NewPromCounter(metrics.WorkerPacketOutTotal),
		WorkerReservationUpdateTotal:  libmetrics.NewPromCounter(metrics.WorkerReservationUpdateTotal),
	}
	return c
}

// Loads the active EE Reservations from the colibri service
func (p *Processor) loadActiveReservationsFromColibriService(ctx context.Context,
	config *config.ColigateConfig, colibiServiceAddr *net.UDPAddr, timeout int) error {

	log.Info("Loading active reservation indices from colibri service")
	var response *copb.ActiveIndicesResponse
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		if time.Now().After(deadline) {
			return serrors.New(
				"Loading active reservation indices from colibri service failed after timeout")
		}
		grpcconn, err := grpc.Dial(colibiServiceAddr.String(), grpc.WithInsecure()) // TODO(rohrerj) add transport security
		if err != nil {
			continue
		}
		copbservice := copb.NewColibriServiceClient(grpcconn)
		response, err = copbservice.ActiveIndices(ctx, &copb.ActiveIndicesRequest{})
		if err != nil {
			continue
		}
		break
	}
	p.metrics.LoadActiveReservationsTotal.Add(float64(len(response.Reservations)))
	for _, respReservation := range response.Reservations {
		highestValidity := time.Unix(0, 0)
		id, err := libtypes.NewID(libaddr.AS(respReservation.Id.Asid), respReservation.Id.Suffix)
		if err != nil {
			log.Debug("error parsing reservation id", "err", err)
			continue
		}
		res := storage.NewReservation(string(id.ToRaw()),
			[]storage.HopField{
				{
					EgressId: uint16(respReservation.Egress),
				},
			})
		for _, respResIndex := range respReservation.Indices {
			resIndex := storage.NewIndex(uint8(respResIndex.Index), util.SecsToTime(respResIndex.ExpirationTime),
				uint8(respResIndex.AllocBw), respResIndex.Sigmas)

			res.Indices[resIndex.Index] = resIndex
			if resIndex.Validity.Sub(highestValidity) > 0 {
				highestValidity = resIndex.Validity
			}
		}
		task := storage.NewUpdateTask(res, highestValidity)

		// Registers the reservation for deletion once it expires
		p.cleanupChannel <- task

		p.controlUpdateChannels[p.getWorkerForResId([]byte(task.Reservation.Id))] <- task
	}
	log.Info("Successfully loaded active reservation indices from colibri service")
	return nil
}

func (p *Processor) getWorkerForResId(resId []byte) uint32 {
	return p.saltHasher.Hash(resId) % uint32(p.numWorkers)
}

// Initializes the cleanup routine that removes outdated reservations
func (p *Processor) initCleanupRoutine() {
	log.Info("Init cleanup routine")

	reservationExpirations := make(map[string]time.Time)

	updateExpirationMapping := (func(task *storage.UpdateTask) {
		p.metrics.CleanupReservationUpdateTotal.Add(1)
		res, exists := reservationExpirations[task.Reservation.Id]
		if !exists || task.HighestValidity.After(res) {
			p.metrics.CleanupReservationUpdateNew.Add(1)
			reservationExpirations[task.Reservation.Id] = task.HighestValidity
		}
	})
	for !p.exit { // TODO(rohrerj) check CPU usage
		if len(reservationExpirations) == 0 {
			task := <-p.cleanupChannel
			if task == nil {
				return
			}
			updateExpirationMapping(task)
		}
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
						val = reservationExpirations[resId] // Updated current value in case it got changed
					}
				default:
					break out
				}
			}
			if time.Until(val) < 0 {
				p.metrics.CleanupReservationDeleted.Add(1)

				p.controlDeletionChannels[p.getWorkerForResId([]byte(resId))] <- storage.NewDeletionTask(resId)
				delete(reservationExpirations, resId)
			}
		}
	}
}

// The function to initialize the control plane of the colibri gateway.
func (p *Processor) initControlPlane(config *config.ColigateConfig, cleanup *app.Cleanup,
	serverAddr *net.TCPAddr) error {

	log.Info("Init control plane")
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
	cgpb.RegisterColibriGatewayServer(s, coligate)
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

		for !p.exit {
			numPkts, err := ipv4Conn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
			if err != nil {
				log.Debug("error while reading from network", "err", err)
				continue
			}
			if numPkts == 0 {
				continue
			}
			log.Debug("received data packets")
			dataPacketInTotalPromCounter.Add(float64(numPkts))
			for _, pkt := range msgs[:numPkts] {
				var d *dataPacket

				d, err = Parse(pkt.Buffers[0][:pkt.N])
				if err != nil {
					log.Debug("error while parsing headers", "err", err)
					dataPacketInInvalidPromCounter.Add(1)
					continue
				}
				if int(d.scionLayer.PayloadLen) != len(d.scionLayer.Payload) || d.scionLayer.PayloadLen != d.colibriPath.InfoField.OrigPayLen {
					// Packet too large or inconsistent payload size.
					continue
				}
				d.pktArrivalTime = time.Now()
				id, err := libtypes.NewID(d.scionLayer.SrcIA.AS(),
					d.colibriPath.InfoField.ResIdSuffix)
				if err != nil {
					log.Debug("cannot parse reservation id")
					continue
				}

				select {
				case p.dataChannels[p.getWorkerForResId(id.ToRaw())] <- d:
				default:
					continue // Packet dropped
				}
			}

		}
		return nil
	})
	return nil
}

// Internal method to get the address of the corresponding border router
// to forward the outgoing packets
func (p *Processor) getBorderRouterConnection(proc *dataPacket) (*ipv4.PacketConn, error) {
	var egressId uint16 = proc.colibriPath.GetCurrentHopField().EgressId
	conn, found := p.borderRouters[egressId]
	if !found {
		return nil, serrors.New("egress interface is invalid:", "egressId", egressId)
	}
	return conn, nil
}

// Configures a goroutine to listen for the data plane channel and control plane reservation updates
func (p *Processor) workerReceiveEntry(config *config.ColigateConfig, workerId uint32,
	gatewayId uint32, localAS libaddr.AS) error {

	log.Info("Init worker", "workerId", workerId)
	worker := NewWorker(config, workerId, gatewayId, localAS)

	workerPacketInTotalPromCounter := p.metrics.WorkerPacketInTotal
	workerPacketInInvalidPromCounter := p.metrics.WorkerPacketInInvalid
	workerPacketOutTotalPromCounter := p.metrics.WorkerPacketOutTotal
	workerReservationUpdateTotalPromCounter := p.metrics.WorkerReservationUpdateTotal

	writeMsgs := make([]ipv4.Message, 1)
	writeMsgs[0].Buffers = [][]byte{make([]byte, bufSize)} // TODO(rohrerj) Check for optimizations

	ch := p.dataChannels[workerId]
	chres := p.controlUpdateChannels[workerId]
	chresD := p.controlDeletionChannels[workerId]

	for !p.exit {
		// Check whether new reservation indices have to be processed. This has priority above the data plane packets.
		select {
		case task := <-chres:
			if task == nil {
				return nil
			}
			log.Debug("Worker received reservation update", "workerId", workerId)
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
			log.Debug("Worker received data packet", "workerId", workerId,
				"resId", string(d.colibriPath.InfoField.ResIdSuffix))
			workerPacketInTotalPromCounter.Add(1)
			borderRouterConn, err := p.getBorderRouterConnection(d)
			if err != nil {
				log.Debug("Error getting border router connection", "err", err)
				workerPacketInInvalidPromCounter.Add(1)
				continue
			}
			if err = worker.process(d); err != nil {
				log.Debug("Worker received error while processing.", "workerId", workerId,
					"error", err.Error())
				workerPacketInInvalidPromCounter.Add(1)
				continue
			}

			writeMsgs[0].Buffers[0] = d.rawPacket

			borderRouterConn.WriteBatch(writeMsgs, syscall.MSG_DONTWAIT)
			workerPacketOutTotalPromCounter.Add(1)
			log.Debug("Worker forwarded packet", "workerId", workerId)
		case task := <-chres:
			if task == nil {
				return nil
			}
			log.Debug("Worker received reservation update", "workerId", workerId)
			workerReservationUpdateTotalPromCounter.Add(1)
			task.Execute(worker.Storage)
		case task := <-chresD: // Reservation deletion received.
			if task == nil {
				return nil
			}
			log.Debug("Worker received reservation deletion", "workerId", workerId)
			workerReservationUpdateTotalPromCounter.Add(1)
			task.Execute(worker.Storage)
		}

	}
	return nil
}
