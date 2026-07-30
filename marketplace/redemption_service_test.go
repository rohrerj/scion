// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package marketplace_test

import (
	"math"
	"testing"
	"time"

	"github.com/scionproto/scion/marketplace"
	"github.com/scionproto/scion/marketplace/db"
	"github.com/stretchr/testify/assert"
)

func TestIDStore(t *testing.T) {
	base, err := time.Parse(time.RFC3339, "2026-07-16T00:00:00Z")
	b := base.Unix()
	assert.NoError(t, err)
	store := marketplace.UsedIDStore{}
	err = store.Init(3, []*db.UsedReservation{
		{
			Id:       0,
			StartsAt: base,
			StopsAt:  base.Add(time.Second * 3),
		},
	})
	assert.NoError(t, err)
	nextId, err := store.Next(b, b, b+1)
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), nextId)
	nextId, err = store.Next(b, b, b+2)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), nextId)
	nextId, err = store.Next(b+1, b+1, b+2)
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), nextId)
	nextId, err = store.Next(b+1, b+1, b+2)
	assert.Error(t, err)
}

func TestEncoding(t *testing.T) {
	const (
		minBwKbps        = 10.0
		maxBwKbps        = 10_000_000.0
		levels           = 1024
		logEncodingStart = 60
	)
	var step = math.Pow(maxBwKbps/(minBwKbps+float64(logEncodingStart)), 1.0/float64(levels-logEncodingStart-1))
	indexToBwKbps := func(i int) int {
		if i < logEncodingStart {
			return i + minBwKbps
		}
		bw := (minBwKbps + logEncodingStart) * math.Pow(step, float64(i-logEncodingStart))
		return int(math.Ceil(bw))
	}
	encodings := make([]uint32, levels)
	for i := 0; i < levels; i++ {
		encodings[i] = uint32(indexToBwKbps(i))
	}
	s := &marketplace.RedemptionService{}
	s.SetEncodingPoints(encodings)
	assert.Equal(t, uint16(0), s.EncodeBandwidth(minBwKbps))
	assert.Equal(t, uint16(1), s.EncodeBandwidth(minBwKbps+1))
	assert.Equal(t, uint16(59), s.EncodeBandwidth(minBwKbps+59))
	assert.Equal(t, uint16(60), s.EncodeBandwidth(minBwKbps+60))
	assert.Equal(t, uint16(levels-1), s.EncodeBandwidth(maxBwKbps))
	assert.Equal(t, uint16(levels-1), s.EncodeBandwidth(math.MaxUint32))
}
