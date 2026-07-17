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

package marketplace

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCombine(t *testing.T) {
	type Test struct {
		duration         time.Duration
		bw               uint32
		splitCombineCost uint64
		assets           []*hummingbird.SearchAsset
		expectedResponse []*hummingbird.BuyAsset
	}
	start, _ := time.Parse(time.RFC3339, "2026-07-07T00:00:00Z")
	tests := map[string]Test{
		"baseCombine": {
			duration: time.Second * 2,
			bw:       1,
			expectedResponse: []*hummingbird.BuyAsset{
				{
					AssetId:         "1",
					StartsAtExactly: timestamppb.New(start),
					StopsAtExactly:  timestamppb.New(start.Add(time.Second * 1)),
					BandwidthExact:  1,
				},
				{
					AssetId:         "2",
					StartsAtExactly: timestamppb.New(start.Add(time.Second * 1)),
					StopsAtExactly:  timestamppb.New(start.Add(time.Second * 2)),
					BandwidthExact:  1,
				},
			},
			assets: []*hummingbird.SearchAsset{
				{
					AssetId:         "1",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start),
					StopsAt:         timestamppb.New(start.Add(time.Second * 1)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           1,
				},
				{
					AssetId:         "2",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start.Add(time.Second * 1)),
					StopsAt:         timestamppb.New(start.Add(time.Second * 2)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           1,
				},
			},
		},
		"baseCombineChooseCheaper": {
			duration: time.Second * 2,
			bw:       1,
			expectedResponse: []*hummingbird.BuyAsset{
				{
					AssetId:         "1",
					StartsAtExactly: timestamppb.New(start),
					StopsAtExactly:  timestamppb.New(start.Add(time.Second * 1)),
					BandwidthExact:  1,
				},
				{
					AssetId:         "3",
					StartsAtExactly: timestamppb.New(start.Add(time.Second * 1)),
					StopsAtExactly:  timestamppb.New(start.Add(time.Second * 2)),
					BandwidthExact:  1,
				},
			},
			assets: []*hummingbird.SearchAsset{
				{
					AssetId:         "1",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start),
					StopsAt:         timestamppb.New(start.Add(time.Second * 1)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           1,
				},
				{
					AssetId:         "2",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start.Add(time.Second * 1)),
					StopsAt:         timestamppb.New(start.Add(time.Second * 2)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           2,
				},
				{
					AssetId:         "3",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start.Add(time.Second * 1)),
					StopsAt:         timestamppb.New(start.Add(time.Second * 2)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           1,
				},
			},
		},
		"combineOverlappingSolutions": {
			duration: time.Second * 5,
			bw:       1,
			expectedResponse: []*hummingbird.BuyAsset{
				{
					AssetId:         "1",
					StartsAtExactly: timestamppb.New(start),
					StopsAtExactly:  timestamppb.New(start.Add(time.Second * 1)),
					BandwidthExact:  1,
				},
				{
					AssetId:         "2",
					StartsAtExactly: timestamppb.New(start.Add(time.Second * 1)),
					StopsAtExactly:  timestamppb.New(start.Add(time.Second * 2)),
					BandwidthExact:  1,
				},
				{
					AssetId:         "3",
					StartsAtExactly: timestamppb.New(start.Add(time.Second * 2)),
					StopsAtExactly:  timestamppb.New(start.Add(time.Second * 4)),
					BandwidthExact:  1,
				},
				{
					AssetId:         "4",
					StartsAtExactly: timestamppb.New(start.Add(time.Second * 4)),
					StopsAtExactly:  timestamppb.New(start.Add(time.Second * 5)),
					BandwidthExact:  1,
				},
			},
			assets: []*hummingbird.SearchAsset{
				{
					AssetId:         "1",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start),
					StopsAt:         timestamppb.New(start.Add(time.Second * 1)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           1,
				},
				{
					AssetId:         "2",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start.Add(time.Second * 1)),
					StopsAt:         timestamppb.New(start.Add(time.Second * 2)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           1,
				},
				{
					AssetId:         "3",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start.Add(time.Second * 1)),
					StopsAt:         timestamppb.New(start.Add(time.Second * 4)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           1,
				},
				{
					AssetId:         "4",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start.Add(time.Second * 4)),
					StopsAt:         timestamppb.New(start.Add(time.Second * 5)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           1,
				},
			},
		},
		"combineOverlappingSolutionsWithCombineCost": {
			duration:         time.Second * 5,
			bw:               1,
			splitCombineCost: 10,
			expectedResponse: []*hummingbird.BuyAsset{
				{
					AssetId:         "1",
					StartsAtExactly: timestamppb.New(start),
					StopsAtExactly:  timestamppb.New(start.Add(time.Second * 1)),
					BandwidthExact:  1,
				},
				{
					AssetId:         "3",
					StartsAtExactly: timestamppb.New(start.Add(time.Second * 1)),
					StopsAtExactly:  timestamppb.New(start.Add(time.Second * 4)),
					BandwidthExact:  1,
				},
				{
					AssetId:         "4",
					StartsAtExactly: timestamppb.New(start.Add(time.Second * 4)),
					StopsAtExactly:  timestamppb.New(start.Add(time.Second * 5)),
					BandwidthExact:  1,
				},
			},
			assets: []*hummingbird.SearchAsset{
				{
					AssetId:         "1",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start),
					StopsAt:         timestamppb.New(start.Add(time.Second * 1)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           1,
				},
				{
					AssetId:         "2",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start.Add(time.Second * 1)),
					StopsAt:         timestamppb.New(start.Add(time.Second * 2)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           1,
				},
				{
					AssetId:         "3",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start.Add(time.Second * 1)),
					StopsAt:         timestamppb.New(start.Add(time.Second * 4)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           1,
				},
				{
					AssetId:         "4",
					Bandwidth:       1,
					StartsAt:        timestamppb.New(start.Add(time.Second * 4)),
					StopsAt:         timestamppb.New(start.Add(time.Second * 5)),
					TimeGranularity: 1,
					BandwidthMin:    1,
					TimeMinDuration: 1,
					Price:           1,
				},
			},
		},
	}
	c := &MarketplaceClient{}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.NotEqual(t, 0, tc.bw)
			buyAssets, _, ok := c.recursiveSelectStart(tc.assets, tc.bw, start, start.Add(tc.duration), tc.splitCombineCost)
			if tc.expectedResponse == nil {
				assert.False(t, ok)
			} else {
				assert.NotEmpty(t, buyAssets)
				assert.Len(t, buyAssets, len(tc.expectedResponse))
				for i := range buyAssets {
					assert.Equal(t, tc.expectedResponse[i].AssetId, buyAssets[i].AssetId)
					assert.Equal(t, tc.expectedResponse[i].StartsAtExactly.Seconds, buyAssets[i].StartsAtExactly.Seconds)
					assert.Equal(t, tc.expectedResponse[i].StopsAtExactly.Seconds, buyAssets[i].StopsAtExactly.Seconds)
					assert.Equal(t, tc.expectedResponse[i].BandwidthExact, buyAssets[i].BandwidthExact)
				}
			}
		})
	}
}
