// Copyright 2023 ETH Zürich
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

package control

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/pkg/log"
	drpb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/drkey"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type SecretValue struct {
	EpochBegin time.Time
	EpochEnd   time.Time
	Key        [16]byte
}

type Fetcher struct {
	localAddr  *net.TCPAddr
	remoteAddr *net.TCPAddr
	dp         Dataplane
}

func NewFetcher(localIP string, csAddr string, dp Dataplane) (*Fetcher, error) {
	localAddr := &net.TCPAddr{
		IP:   net.ParseIP(localIP),
		Port: 0,
	}
	remoteTcpAddr, err := net.ResolveTCPAddr("tcp", csAddr)
	if err != nil {
		return nil, err
	}
	f := &Fetcher{
		localAddr:  localAddr,
		remoteAddr: remoteTcpAddr,
		dp:         dp,
	}
	return f, nil
}

func (f *Fetcher) StartFabridPolicyFetcher() {
	retryAfterErrorDuration := 10 * time.Second
	for {
		policies, err := f.queryFabridPolicies()
		if err != nil {
			log.Debug("Error while querying the FABRID policies from local control service", "err", err)
			time.Sleep(retryAfterErrorDuration)
			continue
		}
		err = f.dp.UpdateFabridPolicies(policies)
		if err != nil {
			log.Debug("Error while adding FABRID policies", "err", err)
			time.Sleep(retryAfterErrorDuration)
			continue
		}
		time.Sleep(30 * time.Minute)
	}
}

func (f *Fetcher) queryFabridPolicies() (map[uint8]uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return net.DialTCP("tcp", f.localAddr, f.remoteAddr)
	}
	grpcconn, err := grpc.DialContext(ctx, f.remoteAddr.String(),
		grpc.WithInsecure(), grpc.WithContextDialer(dialer))
	if err != nil {
		return nil, err
	}
	defer grpcconn.Close()
	return map[uint8]uint32{
		0: 0,
	}, nil
}

func (f *Fetcher) StartSecretUpdater() {
	retryAfterErrorDuration := 10 * time.Second
	for {
		sv, err := f.queryASSecret(drkey.Protocol_PROTOCOL_FABRID)
		if err != nil {
			log.Debug("Error while querying secret value from local control service", "err", err)
			time.Sleep(retryAfterErrorDuration)
			continue
		}
		err = f.dp.AddDRKeySecret(int32(drkey.Protocol_PROTOCOL_FABRID), sv)
		if err != nil {
			log.Debug("Error while adding drkey", "err", err)
			time.Sleep(retryAfterErrorDuration)
			continue
		}
		time.Sleep(time.Until(sv.EpochEnd) - 5*time.Minute)
	}
}

func (f *Fetcher) queryASSecret(
	protocolID drkey.Protocol) (SecretValue, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return net.DialTCP("tcp", f.localAddr, f.remoteAddr)
	}
	grpcconn, err := grpc.DialContext(ctx, f.remoteAddr.String(),
		grpc.WithInsecure(), grpc.WithContextDialer(dialer))
	if err != nil {
		return SecretValue{}, err
	}
	defer grpcconn.Close()
	client := drpb.NewDRKeyIntraServiceClient(grpcconn)
	req := &drpb.DRKeySecretValueRequest{
		ProtocolId: protocolID,
		ValTime:    timestamppb.New(time.Now().Add(1 * time.Hour)),
	}
	res, err := client.DRKeySecretValue(ctx, req)
	if err != nil {
		return SecretValue{}, err
	}
	newKey := [16]byte{}
	copy(newKey[:16], res.Key[:16])
	sv := SecretValue{
		EpochBegin: res.EpochBegin.AsTime(),
		EpochEnd:   res.EpochEnd.AsTime(),
		Key:        newKey,
	}
	return sv, nil
}
