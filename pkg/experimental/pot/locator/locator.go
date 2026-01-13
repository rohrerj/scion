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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

type Hop struct {
	Ingress   uint16
	Egress    uint16
	IA        addr.IA
	IsIngress bool
}

type PacketDrop struct {
	Path       snet.Path
	PacketHash []byte
}

type Bucket struct {
	Ingress           uint32
	Egress            uint32
	Data              []byte
	Counter           uint32
	IsIngress         bool
	SourceIAAggregate *big.Int
}

type Fetcher interface {
	FetchBuckets(ctx context.Context, ia addr.IA) ([]Bucket, error)
	GetBuckets(ctx context.Context, ia addr.IA) (map[Hop]Bucket, error)
	SourceEndhostHashes(ctx context.Context, ia addr.IA) ([]SourceEndhostHash, error)
}

type SourceEndhostHash struct {
	Addr net.Addr
	Data []byte
}

type Locator struct {
	Fetcher Fetcher
}

func NewLocator(sd daemon.Connector, sendTime time.Time, localIA addr.IA, localAddr *net.UDPAddr) *Locator {
	fmt.Println("send time", sendTime)
	return &Locator{
		Fetcher: &fetcher{
			LocalIA:   localIA,
			Daemon:    sd,
			SendTime:  sendTime,
			LocalAddr: localAddr,
		},
	}
}

func aggregate(bucket *Bucket, newBucket *Bucket) error {
	if len(bucket.Data) != len(newBucket.Data) {
		return serrors.New("slices need equal length")
	}
	for i := 0; i < len(bucket.Data); i++ {
		bucket.Data[i] ^= newBucket.Data[i]
	}
	bucket.Counter += newBucket.Counter
	bucket.SourceIAAggregate.Add(bucket.SourceIAAggregate, newBucket.SourceIAAggregate)
	return nil
}

func (l *Locator) LocatePacketDrop(ctx context.Context, p *PacketDrop) ([]addr.IA, error) {
	fmt.Println("start localization")
	hops := p.Path.Metadata().Hops()
	fmt.Println(hops)
	lastIAEgressBucket := &Bucket{}
	lastIA := addr.IA(0)
	for i := 0; i < len(hops); i++ {
		hop := hops[i]
		ia := hop.IA
		//fmt.Println(ia)
		buckets, err := l.Fetcher.GetBuckets(ctx, ia)
		if err != nil {
			return nil, err
		}
		b1 := buckets[Hop{
			Ingress:   uint16(hop.IgIf),
			Egress:    uint16(hop.EgIf),
			IA:        ia,
			IsIngress: true,
		}]
		//fmt.Println(b1.Ingress, b1.Egress, b1.IsIngress, b1.Counter, b1.Data, b1.SourceIAAggregate.String())
		b2 := buckets[Hop{
			Ingress:   uint16(hop.IgIf),
			Egress:    uint16(hop.EgIf),
			IA:        ia,
			IsIngress: false,
		}]
		//fmt.Println(b2.Ingress, b2.Egress, b2.IsIngress, b2.Counter, b2.Data, b2.SourceIAAggregate.String())
		// compute the combined buckets for the ingress and egress router's interface
		fixedIngressBucket := Bucket{
			Data:              make([]byte, 32),
			SourceIAAggregate: big.NewInt(0),
		}
		fixedEgressBucket := Bucket{
			Data:              make([]byte, 32),
			SourceIAAggregate: big.NewInt(0),
		}
		for _, bucket := range buckets {
			if bucket.Ingress == uint32(hop.IgIf) && bucket.IsIngress {
				err = aggregate(&fixedIngressBucket, &bucket)
				if err != nil {
					return nil, err
				}
			}
			if bucket.Egress == uint32(hop.EgIf) && !bucket.IsIngress {
				err = aggregate(&fixedEgressBucket, &bucket)
				if err != nil {
					return nil, err
				}
			}
		}

		// where can we have now packet drops?
		// A) inside AS: b1.Counter != b2.Counter
		// B) between consecutive ASes: lastIA.fixedEgressBucket != currentIA.fixedIngressBucket
		if i != 0 && i != len(hops)-1 && b1.Counter != b2.Counter {
			fmt.Println("Inconsistency inside IA:", ia, b1.Counter, b2.Counter)
		}
		if i != 0 && lastIAEgressBucket.Counter != fixedIngressBucket.Counter {
			fmt.Println("Inconsistency between IAs:", lastIA, ia, lastIAEgressBucket.Counter, fixedIngressBucket.Counter)
		}

		lastIAEgressBucket = &fixedEgressBucket
		lastIA = ia

	}
	// We should have found inconsistencies (printed to console), now we have to backtrace

	return nil, nil
}
