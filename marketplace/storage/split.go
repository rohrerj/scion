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
	"slices"
	"sort"
	"time"

	"github.com/scionproto/scion/marketplace/db"
)

type RequestedSplit struct {
	ExactFrom      time.Time
	ExactTo        time.Time
	ExactBandwidth uint32
}

type AssetSegment struct {
	StartAt   time.Time
	StopAt    time.Time
	Bandwidth uint32
	Used      bool

	requestIndex *int
}

type SplitResult struct {
	Bought []AssetSegment
	Unused []AssetSegment
}

func overlaps(segFrom time.Time, segTo time.Time, req RequestedSplit) bool {
	return segFrom.Before(req.ExactTo) && segTo.After(req.ExactFrom)
}

func validateSplit(asset *db.DBAsset, p RequestedSplit) error {
	if p.ExactFrom.Before(asset.StartAt) || p.ExactTo.After(asset.StopsAt) {
		return fmt.Errorf("purchase outside asset bounds")
	}
	if !p.ExactFrom.Before(p.ExactTo) {
		return fmt.Errorf("invalid validity range")
	}
	if p.ExactFrom.Nanosecond() != 0 || p.ExactTo.Nanosecond() != 0 {
		return fmt.Errorf("timestamps must be second precision")
	}
	if p.ExactBandwidth > asset.Bandwidth {
		return fmt.Errorf("purchase amount exceeds asset amount")
	}

	return nil
}

func sameRequest(a *int, b *int) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func mergeAdjacent(
	segments []AssetSegment,
) []AssetSegment {

	if len(segments) == 0 {
		return nil
	}
	sort.Slice(segments, func(i, j int) bool {
		ai := -1
		aj := -1
		if segments[i].requestIndex != nil {
			ai = *segments[i].requestIndex
		}
		if segments[j].requestIndex != nil {
			aj = *segments[j].requestIndex
		}
		if ai != aj {
			return ai < aj
		}
		if segments[i].Used != segments[j].Used {
			return segments[i].Used
		}
		if segments[i].Bandwidth != segments[j].Bandwidth {
			return segments[i].Bandwidth < segments[j].Bandwidth
		}
		return segments[i].StartAt.Before(segments[j].StartAt)
	})

	out := []AssetSegment{
		segments[0],
	}

	for i := 1; i < len(segments); i++ {
		cur := segments[i]
		last := &out[len(out)-1]
		canMerge := last.StopAt.Equal(cur.StartAt) &&
			last.Bandwidth == cur.Bandwidth &&
			last.Used == cur.Used &&
			sameRequest(last.requestIndex, cur.requestIndex)

		if canMerge {
			last.StopAt = cur.StopAt
		} else {
			out = append(out, cur)
		}
	}

	return out
}

func SplitAsset(
	asset *db.DBAsset,
	purchases []RequestedSplit,
) (*SplitResult, error) {

	if !asset.StartAt.Before(asset.StopsAt) {
		return nil, fmt.Errorf("invalid asset range")
	}

	pointsMap := map[int64]struct{}{
		asset.StartAt.Unix(): {},
		asset.StopsAt.Unix(): {},
	}
	for _, p := range purchases {
		if err := validateSplit(asset, p); err != nil {
			return nil, err
		}
		pointsMap[p.ExactFrom.Unix()] = struct{}{}
		pointsMap[p.ExactTo.Unix()] = struct{}{}
	}

	var points []int64
	for p := range pointsMap {
		points = append(points, p)
	}

	slices.Sort(points)
	result := &SplitResult{}

	for i := 0; i < len(points)-1; i++ {
		segFrom := time.Unix(points[i], 0).UTC()
		segTo := time.Unix(points[i+1], 0).UTC()
		cursor := uint32(0)

		for reqIdx, p := range purchases {
			if !overlaps(segFrom, segTo, p) {
				continue
			}
			endBw := cursor + p.ExactBandwidth

			if endBw > asset.Bandwidth {
				return nil, fmt.Errorf("overbooked interval %v -> %v", segFrom, segTo)
			}
			cursor = endBw
			reqCopy := reqIdx

			s := AssetSegment{
				StartAt:      segFrom,
				StopAt:       segTo,
				Bandwidth:    p.ExactBandwidth,
				Used:         true,
				requestIndex: &reqCopy,
			}

			result.Bought = append(result.Bought, s)
		}

		// leftover capacity
		remaining := asset.Bandwidth - cursor

		if remaining > 0 {
			s := AssetSegment{
				StartAt:   segFrom,
				StopAt:    segTo,
				Bandwidth: remaining,
				Used:      false,
			}
			result.Unused = append(result.Unused, s)
		}
	}
	result.Bought = mergeAdjacent(result.Bought)
	result.Unused = mergeAdjacent(result.Unused)
	return result, nil
}
