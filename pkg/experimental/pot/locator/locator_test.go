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

package locator_test

import (
	"context"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/pot/locator"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/stretchr/testify/assert"
)

type fetcherMock struct {
	buckets             map[addr.IA][]locator.Bucket
	sourceEndhostHashes map[addr.IA]map[uint32][]locator.SourceEndhostHash
}

func (l *fetcherMock) FetchBuckets(ctx context.Context, ia addr.IA) ([]locator.Bucket, error) {
	b, _ := l.buckets[ia]
	return b, nil
}

func (l *fetcherMock) GetBuckets(ctx context.Context, ia addr.IA) (map[locator.Hop]locator.Bucket, error) {
	b, _ := l.buckets[ia]
	m := make(map[locator.Hop]locator.Bucket)
	for _, bucket := range b {
		m[locator.Hop{
			Ingress:   uint16(bucket.Ingress),
			Egress:    uint16(bucket.Egress),
			IA:        ia,
			IsIngress: bucket.IsIngress,
		}] = bucket
	}
	return m, nil
}

func (l *fetcherMock) SourceEndhostHashes(ctx context.Context, ia addr.IA, egress uint32) ([]locator.SourceEndhostHash, error) {
	h := l.sourceEndhostHashes[ia][egress]
	return h, nil
}

func SourceIAAggregate(ias ...addr.IA) *big.Int {
	v := big.NewInt(0)
	for _, ia := range ias {
		v.Add(v, big.NewInt(int64(ia)))
	}
	return v
}

func DataAggregate(datas ...[]byte) []byte {
	d := make([]byte, 32)
	for _, data := range datas {
		for i := 0; i < len(data); i++ {
			d[i] ^= data[i]
		}
	}
	return d
}

func TestLocator(t *testing.T) {
	//			13
	//			|
	//	10	->	11	->	15
	//			|
	//			12
	//			|
	//			14
	send_time := time.Now().Add(-time.Second * 10)
	localIA := addr.MustIAFrom(1, 10)
	ia11 := addr.MustIAFrom(1, 11)
	ia12 := addr.MustIAFrom(1, 12)
	ia13 := addr.MustIAFrom(1, 13)
	ia14 := addr.MustIAFrom(1, 14)
	ia15 := addr.MustIAFrom(1, 15)
	localAddr, err := net.ResolveUDPAddr("udp", "10.0.0.1:3333")
	addr2, err := net.ResolveUDPAddr("udp", "10.0.0.2:3333")
	addr3, err := net.ResolveUDPAddr("udp", "10.0.0.3:3333")
	addr4, err := net.ResolveUDPAddr("udp", "10.0.0.4:3333")
	addr5, err := net.ResolveUDPAddr("udp", "10.0.0.5:3333")
	addr6, err := net.ResolveUDPAddr("udp", "10.0.0.6:3333")
	assert.NoError(t, err)
	packet_hash_source := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	packet_hash_source_ia_different_host := []byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}
	packet_hash_ia11 := []byte{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1}
	packet_hash_ia12 := []byte{1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2}
	packet_hash_ia13 := []byte{2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1}
	packet_hash_ia14 := []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
	l := locator.NewLocator(nil, send_time, localIA, localAddr)
	l.Fetcher = &fetcherMock{
		sourceEndhostHashes: map[addr.IA]map[uint32][]locator.SourceEndhostHash{
			localIA: {
				1: {
					locator.SourceEndhostHash{
						Addr: localAddr,
						IA:   localIA,
						Data: packet_hash_source,
					},
					locator.SourceEndhostHash{
						Addr: addr2,
						IA:   localIA,
						Data: packet_hash_source_ia_different_host,
					},
				},
			},
			ia11: {
				4: {
					locator.SourceEndhostHash{
						Addr: addr3,
						IA:   ia11,
						Data: packet_hash_ia11,
					},
				},
			},
			ia12: {
				6: {
					locator.SourceEndhostHash{
						Addr: addr4,
						IA:   ia12,
						Data: packet_hash_ia12,
					},
				},
			},
			ia13: {
				9: {
					locator.SourceEndhostHash{
						Addr: addr5,
						IA:   ia13,
						Data: packet_hash_ia13,
					},
				},
			},
			ia14: {
				8: {
					locator.SourceEndhostHash{
						Addr: addr6,
						IA:   ia14,
						Data: packet_hash_ia14,
					},
				},
			},
		},
		buckets: map[addr.IA][]locator.Bucket{
			localIA: {
				locator.Bucket{
					Ingress: 0,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_source,
						packet_hash_source_ia_different_host,
					),
					IsIngress: false,
					Counter:   2,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
						localIA,
					),
					IngressIA: localIA,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_source,
						packet_hash_source_ia_different_host,
					),
					IsIngress: true,
					Counter:   2,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
						localIA,
					),
					IngressIA: localIA,
					EgressIA:  ia11,
				},
			},
			ia11: {
				locator.Bucket{
					Ingress: 0,
					Egress:  4,
					Data: DataAggregate(
						packet_hash_ia11,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia11,
					),
					IngressIA: ia11,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  4,
					Data: DataAggregate(
						packet_hash_ia11,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia11,
					),
					IngressIA: ia11,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 2,
					Egress:  4,
					Data: DataAggregate(
						packet_hash_source,
						//packet_hash_source_ia_different_host, //dropped
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
						localIA,
					),
					IngressIA: localIA,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 2,
					Egress:  4,
					Data: DataAggregate(
						packet_hash_source,
						//packet_hash_source_ia_different_host, //dropped
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
						localIA,
					),
					IngressIA: localIA,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 5,
					Egress:  4,
					Data: DataAggregate(
						packet_hash_ia12,
						packet_hash_ia14,
					),
					IsIngress: true,
					Counter:   2,
					SourceIAAggregate: SourceIAAggregate(
						ia12,
						ia13,
					),
					IngressIA: ia12,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 5,
					Egress:  4,
					Data: DataAggregate(
						packet_hash_ia12,
						packet_hash_ia14,
					),
					IsIngress: false,
					Counter:   2,
					SourceIAAggregate: SourceIAAggregate(
						ia12,
						ia14,
					),
					IngressIA: ia12,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 3,
					Egress:  4,
					Data: DataAggregate(
						packet_hash_ia13,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia13,
					),
					IngressIA: ia13,
					EgressIA:  ia15,
				},
				/*locator.Bucket{
					Ingress: 3,
					Egress:  4,
					Data: DataAggregate(
						packet_hash_ia13,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia13,
					),
					IngressIA: ia13,
				},*/ //packet is lost
			},
			ia12: {
				locator.Bucket{
					Ingress: 0,
					Egress:  6,
					Data: DataAggregate(
						packet_hash_ia12,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia12,
					),
					IngressIA: ia12,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  6,
					Data: DataAggregate(
						packet_hash_ia12,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia12,
					),
					IngressIA: ia12,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 7,
					Egress:  6,
					Data: DataAggregate(
						packet_hash_ia14,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia14,
					),
					IngressIA: ia14,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 7,
					Egress:  6,
					Data: DataAggregate(
						packet_hash_ia14,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia14,
					),
					IngressIA: ia14,
					EgressIA:  ia11,
				},
			},
			ia13: {
				locator.Bucket{
					Ingress: 0,
					Egress:  9,
					Data: DataAggregate(
						packet_hash_ia13,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia13,
					),
					IngressIA: ia13,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  9,
					Data: DataAggregate(
						packet_hash_ia13,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia13,
					),
					IngressIA: ia13,
					EgressIA:  ia11,
				},
			},
			ia14: {
				locator.Bucket{
					Ingress: 0,
					Egress:  8,
					Data: DataAggregate(
						packet_hash_ia14,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia14,
					),
					IngressIA: ia14,
					EgressIA:  ia12,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  8,
					Data: DataAggregate(
						packet_hash_ia14,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia14,
					),
					IngressIA: ia14,
					EgressIA:  ia12,
				},
			},
			ia15: {
				locator.Bucket{
					Ingress: 10,
					Egress:  0,
					Data: DataAggregate(
						//packet_hash_source, //dropped
						//packet_hash_source_ia_different_host,  //dropped
						packet_hash_ia11,
						//packet_hash_ia12, //dropped
						//packet_hash_ia13, //dropped
						packet_hash_ia14,
					),
					IsIngress: false,
					Counter:   4,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
						ia11,
						ia13,
						ia14,
					),
					IngressIA: ia11,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 10,
					Egress:  0,
					Data: DataAggregate(
						//packet_hash_source, //dropped
						//packet_hash_source_ia_different_host,  //dropped
						packet_hash_ia11,
						//packet_hash_ia12, //dropped
						//packet_hash_ia13, //dropped
						packet_hash_ia14,
					),
					IsIngress: true,
					Counter:   4,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
						ia11,
						ia13,
						ia14,
					),
					IngressIA: ia11,
					EgressIA:  ia15,
				},
			},
		},
	}
	// since the locator is only interested in the ID and IA of all path interfaces in the metadata,
	// we can simply create the path like this:
	p := path.Path{
		Meta: snet.PathMetadata{
			FabridInfo: make([]snet.FabridInfo, 3),
			Interfaces: []snet.PathInterface{
				{
					ID: 1,
					IA: localIA,
				},
				{
					ID: 2,
					IA: ia11,
				},
				{
					ID: 4,
					IA: ia11,
				},
				{
					ID: 10,
					IA: ia15,
				},
			},
		},
	}
	foundASes, err := l.LocatePacketDrop(context.Background(), &locator.PacketDrop{
		Path:       p,
		PacketHash: packet_hash_source,
	})
	assert.NoError(t, err)
	assert.ElementsMatch(t, []addr.IA{ia11, ia15}, foundASes)
	t.Log(foundASes)
}

func TestLocator2(t *testing.T) {
	//
	//	10	->	11	->	15
	//	|		|
	//	12	-	13
	//			|
	//			14
	send_time := time.Now().Add(-time.Second * 10)
	localIA := addr.MustIAFrom(1, 10)
	ia11 := addr.MustIAFrom(1, 11)
	ia12 := addr.MustIAFrom(1, 12)
	ia13 := addr.MustIAFrom(1, 13)
	ia14 := addr.MustIAFrom(1, 14)
	ia15 := addr.MustIAFrom(1, 15)
	localAddr, err := net.ResolveUDPAddr("udp", "10.0.0.1:3333")
	addr2, err := net.ResolveUDPAddr("udp", "10.0.0.2:3333")
	addr3, err := net.ResolveUDPAddr("udp", "10.0.0.3:3333")
	addr4, err := net.ResolveUDPAddr("udp", "10.0.0.4:3333")
	addr5, err := net.ResolveUDPAddr("udp", "10.0.0.5:3333")
	addr6, err := net.ResolveUDPAddr("udp", "10.0.0.6:3333")
	assert.NoError(t, err)
	packet_hash_source := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	packet_hash_source_2 := []byte{2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64}
	packet_hash_source_ia_different_host := []byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}
	packet_hash_ia11 := []byte{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1}
	packet_hash_ia12 := []byte{1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2}
	packet_hash_ia13 := []byte{2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1}
	packet_hash_ia13_2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	packet_hash_ia14 := []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
	l := locator.NewLocator(nil, send_time, localIA, localAddr)
	l.Fetcher = &fetcherMock{
		sourceEndhostHashes: map[addr.IA]map[uint32][]locator.SourceEndhostHash{
			localIA: {
				1: {
					locator.SourceEndhostHash{
						Addr: localAddr,
						IA:   localIA,
						Data: packet_hash_source,
					},
					locator.SourceEndhostHash{
						Addr: addr2,
						IA:   localIA,
						Data: packet_hash_source_ia_different_host,
					},
				},
				2: {
					locator.SourceEndhostHash{
						Addr: localAddr,
						IA:   localIA,
						Data: packet_hash_source_2,
					},
				},
			},
			ia11: {
				2: {
					locator.SourceEndhostHash{
						Addr: addr3,
						IA:   ia11,
						Data: packet_hash_ia11,
					},
				},
			},
			ia12: {
				1: {
					locator.SourceEndhostHash{
						Addr: addr4,
						IA:   ia12,
						Data: packet_hash_ia12,
					},
				},
			},
			ia13: {
				1: {
					locator.SourceEndhostHash{
						Addr: addr5,
						IA:   ia13,
						Data: packet_hash_ia13,
					},
				},
				3: {
					locator.SourceEndhostHash{
						Addr: addr5,
						IA:   ia13,
						Data: packet_hash_ia13_2,
					},
				},
			},
			ia14: {
				1: {
					locator.SourceEndhostHash{
						Addr: addr6,
						IA:   ia14,
						Data: packet_hash_ia14,
					},
				},
			},
		},
		buckets: map[addr.IA][]locator.Bucket{
			localIA: {
				locator.Bucket{
					Ingress: 0,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_source,
						packet_hash_source_ia_different_host,
					),
					IsIngress: false,
					Counter:   2,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
						localIA,
					),
					IngressIA: localIA,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_source,
						packet_hash_source_ia_different_host,
					),
					IsIngress: true,
					Counter:   2,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
						localIA,
					),
					IngressIA: localIA,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  2,
					Data: DataAggregate(
						packet_hash_source_2,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
					),
					IngressIA: localIA,
					EgressIA:  ia12,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  2,
					Data: DataAggregate(
						packet_hash_source_2,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
					),
					IngressIA: localIA,
					EgressIA:  ia12,
				},
				locator.Bucket{
					Ingress: 2,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_ia12,
						packet_hash_ia13_2,
					),
					IsIngress: false,
					Counter:   2,
					SourceIAAggregate: SourceIAAggregate(
						ia12,
						ia13,
					),
					IngressIA: ia12,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 2,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_ia12,
						packet_hash_ia13_2,
					),
					IsIngress: true,
					Counter:   2,
					SourceIAAggregate: SourceIAAggregate(
						ia12,
						ia13,
					),
					IngressIA: ia12,
					EgressIA:  ia11,
				},
			},
			ia11: {
				locator.Bucket{
					Ingress: 0,
					Egress:  2,
					Data: DataAggregate(
						packet_hash_ia11,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia11,
					),
					IngressIA: ia11,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  2,
					Data: DataAggregate(
						packet_hash_ia11,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia11,
					),
					IngressIA: ia11,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 1,
					Egress:  2,
					Data: DataAggregate(
						packet_hash_source,
						packet_hash_source_ia_different_host,
						packet_hash_ia12,
						packet_hash_ia13_2,
					),
					IsIngress: true,
					Counter:   4,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
						localIA,
						ia12,
						ia13,
					),
					IngressIA: localIA,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 1,
					Egress:  2,
					Data: DataAggregate(
						//packet_hash_source,
						packet_hash_source_ia_different_host,
						packet_hash_ia12,
						packet_hash_ia13_2,
					),
					IsIngress: false,
					Counter:   3,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
						//localIA,
						ia12,
						ia13,
					),
					IngressIA: localIA,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 3,
					Egress:  2,
					Data: DataAggregate(
						packet_hash_ia13,
						packet_hash_ia14,
						//packet_hash_source_2,
					),
					IsIngress: true,
					Counter:   2,
					SourceIAAggregate: SourceIAAggregate(
						ia13,
						ia14,
						//localIA,
					),
					IngressIA: ia13,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 3,
					Egress:  2,
					Data: DataAggregate(
						packet_hash_ia13,
						packet_hash_ia14,
						//packet_hash_source_2,
					),
					IsIngress: false,
					Counter:   2,
					SourceIAAggregate: SourceIAAggregate(
						ia13,
						ia14,
						//localIA,
					),
					IngressIA: ia13,
					EgressIA:  ia15,
				},
			},
			ia12: {
				locator.Bucket{
					Ingress: 0,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_ia12,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia12,
					),
					IngressIA: ia12,
					EgressIA:  localIA,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_ia12,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia12,
					),
					IngressIA: ia12,
					EgressIA:  localIA,
				},
				locator.Bucket{
					Ingress: 2,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_ia13_2,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia14,
					),
					IngressIA: ia13,
					EgressIA:  localIA,
				},
				locator.Bucket{
					Ingress: 2,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_ia13_2,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia14,
					),
					IngressIA: ia13,
					EgressIA:  localIA,
				},
				locator.Bucket{
					Ingress: 1,
					Egress:  2,
					Data: DataAggregate(
						packet_hash_source_2,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
					),
					IngressIA: localIA,
					EgressIA:  ia13,
				},
				locator.Bucket{
					Ingress: 1,
					Egress:  2,
					Data: DataAggregate(
						packet_hash_source_2,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
					),
					IngressIA: localIA,
					EgressIA:  ia13,
				},
			},
			ia13: {
				locator.Bucket{
					Ingress: 0,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_ia13,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia13,
					),
					IngressIA: ia13,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_ia13,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia13,
					),
					IngressIA: ia13,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  3,
					Data: DataAggregate(
						packet_hash_ia13_2,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia13,
					),
					IngressIA: ia13,
					EgressIA:  ia12,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  3,
					Data: DataAggregate(
						packet_hash_ia13_2,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia13,
					),
					IngressIA: ia13,
					EgressIA:  ia12,
				},
				locator.Bucket{
					Ingress: 2,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_ia14,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia14,
					),
					IngressIA: ia14,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 2,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_ia14,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia14,
					),
					IngressIA: ia14,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 3,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_source_2,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
					),
					IngressIA: ia12,
					EgressIA:  ia11,
				},
				locator.Bucket{
					Ingress: 3,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_source_2,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						localIA,
					),
					IngressIA: ia12,
					EgressIA:  ia11,
				},
			},
			ia14: {
				locator.Bucket{
					Ingress: 0,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_ia14,
					),
					IsIngress: false,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia14,
					),
					IngressIA: ia14,
					EgressIA:  ia13,
				},
				locator.Bucket{
					Ingress: 0,
					Egress:  1,
					Data: DataAggregate(
						packet_hash_ia14,
					),
					IsIngress: true,
					Counter:   1,
					SourceIAAggregate: SourceIAAggregate(
						ia14,
					),
					IngressIA: ia14,
					EgressIA:  ia13,
				},
			},
			ia15: {
				locator.Bucket{
					Ingress: 1,
					Egress:  0,
					Data: DataAggregate(
						//packet_hash_source,
						//packet_hash_source_2,
						//packet_hash_source_ia_different_host,
						packet_hash_ia11,
						packet_hash_ia12,
						packet_hash_ia13,
						packet_hash_ia13_2,
						packet_hash_ia14,
					),
					IsIngress: false,
					Counter:   5,
					SourceIAAggregate: SourceIAAggregate(
						//localIA,
						//localIA,
						//localIA,
						ia11,
						ia12,
						ia13,
						ia13,
						ia14,
					),
					IngressIA: ia11,
					EgressIA:  ia15,
				},
				locator.Bucket{
					Ingress: 1,
					Egress:  0,
					Data: DataAggregate(
						//packet_hash_source,
						//packet_hash_source_2,
						//packet_hash_source_ia_different_host,
						packet_hash_ia11,
						packet_hash_ia12,
						packet_hash_ia13,
						packet_hash_ia13_2,
						packet_hash_ia14,
					),
					IsIngress: true,
					Counter:   5,
					SourceIAAggregate: SourceIAAggregate(
						//localIA,
						//localIA,
						//localIA,
						ia11,
						ia12,
						ia13,
						ia13,
						ia14,
					),
					IngressIA: ia11,
					EgressIA:  ia15,
				},
			},
		},
	}
	// since the locator is only interested in the ID and IA of all path interfaces in the metadata,
	// we can simply create the path like this:
	p1 := path.Path{
		Meta: snet.PathMetadata{
			FabridInfo: make([]snet.FabridInfo, 3),
			Interfaces: []snet.PathInterface{
				{
					ID: 1,
					IA: localIA,
				},
				{
					ID: 1,
					IA: ia11,
				},
				{
					ID: 2,
					IA: ia11,
				},
				{
					ID: 1,
					IA: ia15,
				},
			},
		},
	}
	foundASes, err := l.LocatePacketDrop(context.Background(), &locator.PacketDrop{
		Path:       p1,
		PacketHash: packet_hash_source,
	})
	assert.NoError(t, err)
	assert.ElementsMatch(t, []addr.IA{ia11}, foundASes)
	t.Log(foundASes)

	p2 := path.Path{
		Meta: snet.PathMetadata{
			FabridInfo: make([]snet.FabridInfo, 5),
			Interfaces: []snet.PathInterface{
				{
					ID: 2,
					IA: localIA,
				},
				{
					ID: 1,
					IA: ia12,
				},
				{
					ID: 2,
					IA: ia12,
				},
				{
					ID: 3,
					IA: ia13,
				},
				{
					ID: 1,
					IA: ia13,
				},
				{
					ID: 3,
					IA: ia11,
				},
				{
					ID: 2,
					IA: ia11,
				},
				{
					ID: 1,
					IA: ia15,
				},
			},
		},
	}
	foundASes, err = l.LocatePacketDrop(context.Background(), &locator.PacketDrop{
		Path:       p2,
		PacketHash: packet_hash_source_2,
	})
	assert.NoError(t, err)
	assert.ElementsMatch(t, []addr.IA{ia11, ia13}, foundASes)
	t.Log(foundASes)
}
