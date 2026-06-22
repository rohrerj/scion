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

package storage

import (
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/scionproto/scion/marketplace/db"
	"github.com/stretchr/testify/assert"
)

func BenchmarkSplit(b *testing.B) {

	parse := func(v string) time.Time {
		t, _ := time.Parse("2006-01-02T15:04:05", v)
		return t.UTC()
	}

	asset := &db.DBAsset{
		StartAt:         parse("2026-01-01T00:00:00"),
		StopsAt:         parse("2026-12-31T23:59:59"),
		Bandwidth:       2000,
		BandwidthMin:    100,
		TimeGranularity: 1,
		TimeMinDuration: 1,
		Price:           10,
	}

	tests := []struct {
		name string
		n    int
	}{
		{"n=1", 1},
		{"n=5", 5},
		{"n=10", 10},
		{"n=25", 25},
		{"n=50", 50},
		{"n=100", 100},
		{"n=200", 200},
		{"n=500", 500},
		{"n=1000", 1000},
	}

	for _, tc := range tests {

		b.Run(tc.name, func(b *testing.B) {

			purchases := generatePurchases(parse, tc.n)

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := SplitAsset(asset, purchases)
				if err != nil {
					fmt.Println(purchases)
					b.Fatal(err)
				}
			}
		})
	}
}

func generatePurchases(
	parse func(string) time.Time,
	n int,
) []RequestedSplit {

	base := parse("2026-03-01T00:00:00")

	p := make([]RequestedSplit, n)

	for i := 0; i < n; i++ {

		start := base.Add(time.Duration(i*30) * time.Second)
		end := start.Add(1 * time.Minute)

		bw := uint32(100 + (i%5)*50)

		p[i] = RequestedSplit{
			ExactFrom:      start,
			ExactTo:        end,
			ExactBandwidth: bw,
		}
	}

	return p
}

func TestSplit(t *testing.T) {
	parse := func(v string) time.Time {
		t, _ := time.Parse("2006-01-02T15:04:05", v)
		return t.UTC()
	}

	asset := &db.DBAsset{
		StartAt:   parse("2026-05-22T10:13:57"),
		StopsAt:   parse("2026-05-23T10:13:57"),
		Bandwidth: 2000,

		BandwidthMin: 100,

		TimeGranularity: 1,
		TimeMinDuration: 1,
		Price:           10,
	}

	purchases := []RequestedSplit{
		{
			ExactFrom:      parse("2026-05-22T12:00:00"),
			ExactTo:        parse("2026-05-22T12:10:00"),
			ExactBandwidth: 100,
		},
		{
			ExactFrom:      parse("2026-05-22T12:01:00"),
			ExactTo:        parse("2026-05-22T12:02:00"),
			ExactBandwidth: 100,
		},
		{
			ExactFrom:      parse("2026-05-22T12:00:00"),
			ExactTo:        parse("2026-05-22T12:09:00"),
			ExactBandwidth: 200,
		},
	}

	result, err := SplitAsset(asset, purchases)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("=== BOUGHT ===")
	for _, s := range result.Bought {
		fmt.Printf(
			"%s -> %s bw=%d\n",
			s.StartAt.Format(time.RFC3339),
			s.StopAt.Format(time.RFC3339),
			s.Bandwidth,
		)
	}

	fmt.Println("\n=== UNUSED ===")
	for _, s := range result.Unused {
		fmt.Printf(
			"%s -> %s bw=%d\n",
			s.StartAt.Format(time.RFC3339),
			s.StopAt.Format(time.RFC3339),
			s.Bandwidth,
		)
	}

	fmt.Println("\n=== REMOVE ===")
	for _, s := range result.Remove {
		fmt.Printf(
			"%s -> %s amount=%d used=%v\n",
			s.StartAt.Format(time.RFC3339),
			s.StopAt.Format(time.RFC3339),
			s.Bandwidth,
			s.Used,
		)
	}
	t.Fail()
}

func FuzzSplitAsset(f *testing.F) {

	f.Fuzz(func(
		t *testing.T,

		requestCount uint8,
	) {

		base := time.Unix(0, 0).UTC()

		asset := &db.DBAsset{
			StartAt:         base,
			StopsAt:         base.Add(24 * time.Hour),
			Bandwidth:       1000,
			BandwidthMin:    1,
			TimeGranularity: 1,
			TimeMinDuration: 1,
			Price:           1,
		}

		var purchases []RequestedSplit

		n := int(requestCount % 20)

		for i := 0; i < n; i++ {

			start := time.Duration(i*60) * time.Second

			duration := time.Duration((i%10)+1) * time.Minute

			bw := uint32((i%20)+1) * 10

			purchases = append(
				purchases,
				RequestedSplit{
					ExactFrom:      base.Add(start),
					ExactTo:        base.Add(start).Add(duration),
					ExactBandwidth: bw,
				},
			)
		}

		result, err := SplitAsset(
			asset,
			purchases,
		)

		assert.NoError(t, err)

		verifyNoOverbooking(
			t,
			asset,
			result,
		)

		verifyRequestsSatisfied(
			t,
			purchases,
			result,
		)

		verifyMergeIdempotent(
			t,
			result,
		)
	})
}

func verifyNoOverbooking(
	t *testing.T,
	asset *db.DBAsset,
	result *SplitResult,
) {

	type usage struct {
		used uint32
	}

	m := map[int64]*usage{}

	for _, s := range result.Bought {

		for ts := s.StartAt.Unix(); ts < s.StopAt.Unix(); ts++ {

			u := m[ts]

			if u == nil {
				u = &usage{}
				m[ts] = u
			}

			u.used += s.Bandwidth

			if u.used > asset.Bandwidth {

				t.Fatalf(
					"overbooked at %d: %d > %d",
					ts,
					u.used,
					asset.Bandwidth,
				)
			}
		}
	}
}

func verifyRequestsSatisfied(
	t *testing.T,
	purchases []RequestedSplit,
	result *SplitResult,
) {

	for _, p := range purchases {

		found := false

		for _, s := range result.Bought {

			if s.StartAt.Equal(p.ExactFrom) &&
				s.StopAt.Equal(p.ExactTo) &&
				s.Bandwidth == p.ExactBandwidth {

				found = true
				break
			}
		}

		if !found {

			t.Fatalf(
				"purchase not reconstructed: %+v",
				p,
			)
		}
	}
}

func verifyMergeIdempotent(
	t *testing.T,
	result *SplitResult,
) {

	a := mergeAdjacent(result.Bought)
	b := mergeAdjacent(a)

	if len(a) != len(b) {

		t.Fatalf(
			"merge not idempotent",
		)
	}
}
