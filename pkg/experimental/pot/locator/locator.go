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
	"bytes"
	"context"
	"fmt"
	"math/big"
	"net"
	"slices"
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
	IngressIA         addr.IA
	EgressIA          addr.IA
}

type Fetcher interface {
	FetchBuckets(ctx context.Context, ia addr.IA) ([]Bucket, error)
	GetBuckets(ctx context.Context, ia addr.IA) (map[Hop]Bucket, error)
	SourceEndhostHashes(ctx context.Context, ia addr.IA, egress uint32) ([]SourceEndhostHash, error)
}

type SourceEndhostHash struct {
	Addr net.Addr
	IA   addr.IA
	Data []byte
}

type Locator struct {
	Fetcher Fetcher
}

type dropLocation struct {
	Hashes         []SourceEndhostHash
	Aggregate1     []byte
	Aggregate2     []byte
	RespondingASes []addr.IA
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
	dropLocations := make([]dropLocation, 0, 10)
	for i := 0; i < len(hops); i++ {
		hop := hops[i]
		ia := hop.IA
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
			Ingress:           uint32(hop.IgIf),
			Counter:           0,
		}
		fixedEgressBucket := Bucket{
			Data:              make([]byte, 32),
			SourceIAAggregate: big.NewInt(0),
			Egress:            uint32(hop.EgIf),
			Counter:           0,
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
		if i != 0 && i != len(hops)-1 && (b1.Counter != b2.Counter || !bytes.Equal(b1.Data, b2.Data)) {
			fmt.Println("Inconsistency inside IA:", ia, b1.Counter, b2.Counter)
			// TODO: write unit test to test this case
			h, err := l.recursiveFind(ctx, lastIA, uint32(hops[i-1].EgIf))
			if err != nil {
				return nil, err
			}
			dropLocations = append(dropLocations, dropLocation{
				Hashes:         h,
				Aggregate1:     b1.Data,
				Aggregate2:     b2.Data,
				RespondingASes: []addr.IA{hop.IA},
			})
		}
		// B) between consecutive ASes: lastIA.fixedEgressBucket != currentIA.fixedIngressBucket
		if i != 0 && (lastIAEgressBucket.Counter != fixedIngressBucket.Counter || !bytes.Equal(lastIAEgressBucket.Data, fixedIngressBucket.Data)) {
			fmt.Println("Inconsistency between IAs:", lastIA, ia, lastIAEgressBucket.Counter, fixedIngressBucket.Counter)
			h, err := l.recursiveFind(ctx, lastIA, uint32(hops[i-1].EgIf))
			if err != nil {
				return nil, err
			}
			dropLocations = append(dropLocations, dropLocation{
				Hashes:         h,
				Aggregate1:     lastIAEgressBucket.Data,
				Aggregate2:     fixedIngressBucket.Data,
				RespondingASes: []addr.IA{lastIA, hop.IA},
			})
		}

		lastIAEgressBucket = &fixedEgressBucket
		lastIA = ia

	}
	// We should have found inconsistencies (printed to console), now we have to backtrace
	for _, drop := range dropLocations {
		lostPackets := l.solveLSE(drop)
		fmt.Println("lostPackets", lostPackets, drop.RespondingASes)
		for _, pkt := range lostPackets {
			if slices.Equal(p.PacketHash, pkt.Data) {
				fmt.Printf("Own packet loss: %s\n", pkt.Addr)
				return drop.RespondingASes, nil
			} else {
				fmt.Printf("External packet loss: %s\n", pkt.Addr)
			}
		}
	}
	return nil, serrors.New("Drop location not found")
}

func bytesToBitsMSB(data []byte) []uint8 {
	bits := make([]uint8, 0, len(data)*8)
	for _, b := range data {
		for i := uint(0); i < 8; i++ {
			bits = append(bits, uint8((b>>(7-i))&1))
		}
	}
	return bits
}

func xor(agg1 []byte, agg2 []byte) []byte {
	if len(agg1) != len(agg2) {
		return nil
	}
	res := make([]byte, len(agg1))
	for i := 0; i < len(agg1); i++ {
		res[i] = agg1[i] ^ agg2[i]
	}
	return res
}

func (l *Locator) solveLSE(d dropLocation) []SourceEndhostHash {
	/*fmt.Println("solveLSE")
	fmt.Println(d.Aggregate1)
	fmt.Println(d.Aggregate2)
	for _, h := range d.Hashes {
		fmt.Println(h)
	}*/
	bitstrings := make([][]uint8, len(d.Hashes))
	for i := 0; i < len(d.Hashes); i++ {
		bitstrings[i] = bytesToBitsMSB(d.Hashes[i].Data)
	}
	A := make([][]uint8, 256)
	for i := 0; i < 256; i++ {
		A[i] = make([]uint8, len(bitstrings))
		for j := 0; j < len(bitstrings); j++ {
			A[i][j] = bitstrings[j][i]
		}
	}
	//fmt.Println("A=")
	//fmt.Println(A)
	b := bytesToBitsMSB(xor(d.Aggregate1, d.Aggregate2))
	//fmt.Println("b=")
	//fmt.Println(b)
	//solve lse*x=b
	x := SolveGF2LSE(A, b)
	//fmt.Println("x=")
	//fmt.Println(x)
	sol := make([]SourceEndhostHash, 0, 1)
	for i, index := range x {
		if index == 1 {
			sol = append(sol, d.Hashes[i])
		}
	}
	return sol
}

func (l *Locator) findEgressOfIngressIA(ctx context.Context, ia addr.IA, egressIA addr.IA) (uint32, error) {
	fmt.Printf("findEgressOfEgressIA ia %s egressIA %s\n", ia, egressIA)
	buckets, err := l.Fetcher.GetBuckets(ctx, egressIA)
	if err != nil {
		return 0, err
	}
	// WARNING: this code only works under the assumption that the 'ia' and 'egressIA' are directly connected only over a single link
	for k, v := range buckets {
		fmt.Println(v.IngressIA, v.EgressIA)
		if v.EgressIA == ia {
			return uint32(k.Egress), nil
		}
	}
	return 0, serrors.New("egress not found")
}

func (l *Locator) recursiveFind(ctx context.Context, ia addr.IA, egress uint32) ([]SourceEndhostHash, error) {
	fmt.Printf("recursiveFind %s with egress %d\n", ia, egress)
	h := make([]SourceEndhostHash, 0, 10)
	buckets, err := l.Fetcher.GetBuckets(ctx, ia)
	if err != nil {
		//fmt.Printf("end1 recursiveFind %s with egress %d\n", ia, egress)
		return nil, err
	}
	for k, v := range buckets {
		//we consider only ingress buckets
		if k.IsIngress && k.Egress == uint16(egress) {
			//there should always exist a corresponding egress bucket, if not, packet drop between ingress and egress in that IA
			otherBucket, found := buckets[Hop{
				Ingress:   k.Ingress,
				Egress:    k.Egress,
				IA:        k.IA,
				IsIngress: false,
			}]
			if !found || v.Counter != otherBucket.Counter {
				fmt.Printf("Packet loss in IA %s between %d -> %d\n", k.IA, k.Ingress, k.Egress)
			}
			if k.Ingress == 0 {
				childHashes, err := l.Fetcher.SourceEndhostHashes(ctx, ia, uint32(k.Egress))
				if err != nil {
					//fmt.Printf("end5 recursiveFind %s with egress %d\n", ia, egress)
					return nil, err
				}
				for _, seh := range childHashes {
					h = append(h, seh)
				}
			} else {
				childEgress, err := l.findEgressOfIngressIA(ctx, ia, v.IngressIA)
				if err != nil {
					//fmt.Printf("end2 recursiveFind %s with egress %d\n", ia, egress)
					return nil, err
				}
				childHashes, err := l.recursiveFind(ctx, v.IngressIA, childEgress)
				if err != nil {
					//fmt.Printf("end3 recursiveFind %s with egress %d\n", ia, egress)
					return nil, err
				}
				for _, seh := range childHashes {
					h = append(h, seh)
				}
			}
		}
	}
	//fmt.Printf("end4 recursiveFind %s with egress %d\n", ia, egress)
	return h, nil
}
