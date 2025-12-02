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
	"net"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
)

type Hop struct {
	Ingress uint16
	Egress  uint16
	IA      addr.IA
}

type PacketDrop struct {
	SendTime   time.Time
	Path       []Hop
	PacketHash []byte
}

type Locator struct {
	fetcher *fetcher
}

func NewLocator(sd daemon.Connector, sendTime time.Time, localIA addr.IA, localAddr *net.UDPAddr) *Locator {
	return &Locator{
		fetcher: &fetcher{
			LocalIA:   localIA,
			Daemon:    sd,
			SendTime:  sendTime,
			LocalAddr: localAddr,
		},
	}
}

func (l *Locator) LocatePacketDrop(ctx context.Context, p *PacketDrop) ([]addr.IA, error) {

	return nil, nil
}

func aggregate(bucket Bucket, newValue []byte, counter uint32) error {
	if len(bucket.data) != len(newValue) {
		return serrors.New("slices need equal length")
	}
	for i := 0; i < len(bucket.data); i++ {
		bucket.data[i] ^= newValue[i]
	}
	bucket.counter += counter
	return nil
}

func (l *Locator) compareConsecutiveBuckets(ctx context.Context, p *PacketDrop, index int) error {
	/*ingressASBucket, err := l.fetcher.GetBucket(ctx, p.Path[index].IA, p.Path[index].Ingress, &p.Path[index].Egress)
	if err != nil {
		return err
	}
	allASBuckets, err := l.fetcher.GetBuckets(ctx, p.Path[index].IA)
	//aggregate relevant buckets
	tmpBucket := Bucket{
		data: make([]byte, 32),
	}
	for hop, bucket := range allASBuckets {
		if hop.Egress == p.Path[index].Egress {
			aggregate(tmpBucket, bucket.data, bucket.counter)
		}
	}*/
	return nil

}
