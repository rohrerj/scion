// Copyright 2025 ETH Zurich
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

package locator

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"time"

	"google.golang.org/grpc/resolver"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/proof_of_forwarding"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/svc"
)

type svcRouter struct {
	Connector daemon.Connector
}

func (r svcRouter) GetUnderlay(svc addr.SVC) (*net.UDPAddr, error) {
	return daemon.TopoQuerier{Connector: r.Connector}.UnderlayAnycast(context.TODO(), svc)
}

type fetcher struct {
	LocalIA     addr.IA
	Daemon      daemon.Connector
	SendTime    time.Time
	LocalAddr   *net.UDPAddr
	bucketStore map[addr.IA]map[Hop]Bucket
}

func (l *fetcher) GetBuckets(ctx context.Context, ia addr.IA) (map[Hop]Bucket, error) {
	if l.bucketStore == nil {
		l.bucketStore = make(map[addr.IA]map[Hop]Bucket)
	}
	v, found := l.bucketStore[ia]
	if found {
		return v, nil
	}
	b, err := l.FetchBuckets(ctx, ia)
	if err == nil {
		l.bucketStore[ia] = make(map[Hop]Bucket)
		for _, bucket := range b {
			l.bucketStore[ia][Hop{
				IA:        ia,
				Ingress:   uint16(bucket.Ingress),
				Egress:    uint16(bucket.Egress),
				IsIngress: bucket.IsIngress,
			}] = bucket
		}
	}
	v, found = l.bucketStore[ia]
	if found {
		return v, nil
	}
	return nil, err
}

func (l *fetcher) GetBucket(ctx context.Context, ia addr.IA, ingress uint16, egress uint16, isIngress bool) (Bucket, error) {
	buckets, err := l.GetBuckets(ctx, ia)
	if err != nil {
		return Bucket{}, err
	}
	bucket, found := buckets[Hop{
		IA:        ia,
		Ingress:   ingress,
		Egress:    egress,
		IsIngress: isIngress,
	}]
	if found {
		return bucket, nil
	}
	return Bucket{}, serrors.New("bucket expected but not found")
}

func (l *fetcher) SourceEndhostHashes(ctx context.Context, ia addr.IA) ([]SourceEndhostHash, error) {
	// TODO: implement this
	return nil, nil
}

func (l *fetcher) FetchBuckets(ctx context.Context, ia addr.IA) ([]Bucket, error) {
	var bucket_store_address *snet.SVCAddr
	var dialer libgrpc.Dialer
	if ia == l.LocalIA {
		bucket_store_address = &snet.SVCAddr{
			SVC: addr.SvcBS,
			IA:  ia,
		}
		dialer = &libgrpc.TCPDialer{
			SvcResolver: func(hs addr.SVC) []resolver.Address {
				// Do the SVC resolution

				entries, err := l.Daemon.SVCInfo(ctx, []addr.SVC{hs})
				if err != nil {
					fmt.Printf("Failed to resolve SVC address: %s\n", err)
					return nil
				}
				fmt.Println(hs, entries)
				resolved, ok := entries[hs]
				if !ok {
					fmt.Printf("No SVC address found. [svc=%s]\n", hs)
					return nil
				}
				// Filter the returned addresses.
				addrs := make([]resolver.Address, 0, len(resolved))
				for _, addr := range resolved {
					_, _, err := net.SplitHostPort(addr)
					if err != nil {
						fmt.Printf("Failed to parse addr %s: %s\n", addr, err)
						continue
					}
					addrs = append(addrs, resolver.Address{Addr: addr})
				}
				// Check if localhost is part of the filtered list and if yes, move
				// it to the front.
				/*for i, a := range addrs {
					h, _, err := net.SplitHostPort(a.Addr)
					if err != nil {
						// We already made sure that the address is valid.
						panic(err)
					}
					if h == envFlags.Local().String() {
						addrs[0], addrs[i] = addrs[i], addrs[0]
						break
					}
				}*/
				return addrs
			},
		}
	} else {
		paths, err := l.Daemon.Paths(ctx, ia, l.LocalIA, daemon.PathReqFlags{})
		if err != nil {
			return nil, err
		}
		path := paths[0]
		bucket_store_address = &snet.SVCAddr{
			IA:      path.Destination(),
			Path:    path.Dataplane(),
			NextHop: path.UnderlayNextHop(),
			SVC:     addr.SvcBS,
		}
		nc := appnet.NetworkConfig{
			IA:          l.LocalIA,
			Public:      l.LocalAddr,
			SVCResolver: svcRouter{Connector: l.Daemon},
			Topology:    l.Daemon,
			QUIC:        appnet.QUIC{},
		}
		quicStack, err := nc.QUICStack()
		if err != nil {
			return nil, serrors.WrapStr("initializing QUIC stack", err)
		}
		dialer = &libgrpc.QUICDialer{
			Rewriter: appnet.AddressRewriter{
				SVCRouter: svcRouter{Connector: l.Daemon},
				Router: &snet.BaseRouter{
					Querier: daemon.Querier{
						Connector: l.Daemon,
						IA:        l.LocalIA,
					},
				},
				Resolver: &svc.Resolver{
					LocalIA: l.LocalIA,
					Network: &snet.SCIONNetwork{
						Topology: l.Daemon,
					},
					LocalIP: l.LocalAddr.IP,
				},
			},
			Dialer: quicStack.InsecureDialer,
		}
	}

	conn, err := dialer.Dial(ctx, bucket_store_address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := proof_of_forwarding.NewBucketStoreClient(conn)
	resp, err := client.Query(ctx, &proof_of_forwarding.QueryRequest{
		SendTime: timestamppb.New(l.SendTime),
	})
	if err != nil {
		return nil, err
	}
	res := make([]Bucket, 0, len(resp.Entries))
	for _, entry := range resp.Entries {
		var iaAggr big.Int
		iaAggr.SetString(entry.SourceIaAggregate, 10)
		res = append(res, Bucket{
			Ingress:           entry.Ingress,
			Egress:            entry.Egress,
			Data:              entry.Bucket,
			Counter:           entry.Counter,
			IsIngress:         entry.IsIngress,
			SourceIAAggregate: &iaAggr,
		})
	}
	return res, nil
}
