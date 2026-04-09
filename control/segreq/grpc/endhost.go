// Copyright 2026 ETH Zurich
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

package grpc

import (
	"context"
	"sort"
	"strconv"

	"github.com/scionproto/scion/control/segreq"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	ehpb "github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/segment"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/trust"
)

// LookupServer handles path segment lookups.
type EndhostServer struct {
	Lookuper Lookuper
	//Requests         metrics.Counter
	//UpSegmentsSent   metrics.Counter
	//CoreSegmentsSent metrics.Counter
	//DownSegmentsSent metrics.Counter
	LocalIA   addr.IA
	IsCore    bool
	Inspector trust.Inspector
	PathDB    pathdb.DB
}
type combinedPath struct {
	UpSegment   *seg.PathSegment
	CoreSegment *seg.PathSegment
	DownSegment *seg.PathSegment
}

func (c *combinedPath) Length() int {
	l := 0
	if c.UpSegment != nil {
		l += len(c.UpSegment.ASEntries)
	}
	if c.CoreSegment != nil {
		l += len(c.CoreSegment.ASEntries)
	}
	if c.DownSegment != nil {
		l += len(c.DownSegment.ASEntries)
	}
	return l
}

func (s EndhostServer) ListSegments(ctx context.Context,
	req *ehpb.ListSegmentsRequest) (*ehpb.ListSegmentsResponse, error) {

	src, dst := addr.IA(req.SrcIsdAs), addr.IA(req.DstIsdAs)
	logger := log.FromCtx(ctx)
	logger.Debug("Received ListSegments request", "src", src, "dst", dst)
	res := &ehpb.ListSegmentsResponse{}
	if src == dst {
		// local AS path, no segments are returned
		return res, nil
	}
	pagination, err := strconv.Atoi(req.PageToken)
	if err != nil {
		pagination = 0
	}
	pageSize := req.PageSize
	if req.PageSize == 0 {
		pageSize = 64
	}
	splitter := segreq.NewSplitter(s.LocalIA, s.IsCore, s.Inspector, s.PathDB)
	reqs, err := splitter.Split(ctx, dst)
	if err != nil {
		return nil, err
	}

	upSegments := make(seg.Segments, 0, 1)
	coreSegments := make(seg.Segments, 0, 1)
	downSegments := make(seg.Segments, 0, 1)
	for i := 0; i < len(reqs); i++ {
		segs, err := s.Lookuper.LookupSegments(ctx, reqs[i].Src, reqs[i].Dst)
		if err != nil {
			return nil, err
		}
		for _, meta := range segs {
			switch meta.Type {
			case segment.TypeCore:
				coreSegments = append(coreSegments, meta.Segment)
			case segment.TypeDown:
				downSegments = append(downSegments, meta.Segment)
			case segment.TypeUp:
				upSegments = append(upSegments, meta.Segment)
			}
		}
	}
	allPaths := make([]combinedPath, 0, 1)
	// check for single segment paths:
	isSingleSegment := false
	if len(upSegments) == 0 && len(coreSegments) == 0 {
		isSingleSegment = true
		for _, downSegment := range downSegments {
			allPaths = append(allPaths, combinedPath{DownSegment: downSegment})
		}
	} else if len(upSegments) == 0 && len(downSegments) == 0 {
		isSingleSegment = true
		for _, coreSegment := range coreSegments {
			allPaths = append(allPaths, combinedPath{CoreSegment: coreSegment})
		}
	} else if len(coreSegments) == 0 && len(downSegments) == 0 {
		isSingleSegment = true
		for _, upSegment := range upSegments {
			allPaths = append(allPaths, combinedPath{UpSegment: upSegment})
		}
	}
	if !isSingleSegment {
		if len(upSegments) != 0 {
			// we have up + core + down, up + core, or up + down paths
			for _, upSegment := range upSegments {
				for _, coreSegment := range coreSegments {
					if upSegment.FirstIA() == coreSegment.FirstIA() || upSegment.FirstIA() == coreSegment.LastIA() {
						if len(downSegments) != 0 {
							// we have up segment, core segment and down segment
							for _, downSegment := range downSegments {
								if coreSegment.FirstIA() == downSegment.FirstIA() || coreSegment.LastIA() == downSegment.FirstIA() {
									allPaths = append(allPaths, combinedPath{
										UpSegment:   upSegment,
										CoreSegment: coreSegment,
										DownSegment: downSegment,
									})
								}
							}
						} else {
							// we have up segment and core segment, but no down segment
							allPaths = append(allPaths, combinedPath{
								UpSegment:   upSegment,
								CoreSegment: coreSegment,
							})
						}
					}
				}
				for _, downSegment := range downSegments {
					if upSegment.FirstIA() == downSegment.FirstIA() {
						// we have up segment and down segment, without a core segment
						allPaths = append(allPaths, combinedPath{
							UpSegment:   upSegment,
							DownSegment: downSegment,
						})
					}
				}
			}
		} else {
			// we have only core + down paths
			for _, coreSegment := range coreSegments {
				for _, downSegment := range downSegments {
					if coreSegment.FirstIA() == downSegment.FirstIA() || coreSegment.LastIA() == downSegment.FirstIA() {
						allPaths = append(allPaths, combinedPath{
							CoreSegment: coreSegment,
							DownSegment: downSegment,
						})
					}
				}
			}
		}
	}
	sort.Slice(allPaths, func(i, j int) bool {
		return allPaths[i].Length() < allPaths[j].Length()
	})
	resUp, resCore, resDown, nextPage := selectSegments(allPaths, int(pageSize), pagination)
	res.NextPageToken = strconv.Itoa(nextPage)
	for _, segment := range resUp {
		res.UpSegments = append(res.UpSegments, seg.PathSegmentToPB(segment))
	}
	for _, segment := range resCore {
		res.CoreSegments = append(res.CoreSegments, seg.PathSegmentToPB(segment))
	}
	for _, segment := range resDown {
		res.DownSegments = append(res.DownSegments, seg.PathSegmentToPB(segment))
	}

	logger.Debug("Replied with segments", "up", len(res.UpSegments), "core", len(res.CoreSegments), "down", len(res.DownSegments))
	return res, nil
}

func selectSegments(paths []combinedPath, pageSize int, pagination int) ([]*seg.PathSegment, []*seg.PathSegment, []*seg.PathSegment, int) {
	up := []*seg.PathSegment{}
	core := []*seg.PathSegment{}
	down := []*seg.PathSegment{}

	target := pageSize / 3
	upCount, coreCount, downCount := 0, 0, 0
	used := make(map[*seg.PathSegment]struct{})

	start := (pagination * (pageSize + 1)) % len(paths)
	for i := 0; i < len(paths); i++ {
		idx := (start + i) % len(paths)
		p := paths[idx]
		if upCount+coreCount+downCount >= pageSize {
			break
		}

		score := 0

		if p.UpSegment != nil {
			if _, ok := used[p.UpSegment]; !ok {
				if upCount < target {
					score++
				}
			}
		}
		if p.CoreSegment != nil {
			if _, ok := used[p.CoreSegment]; !ok {
				if coreCount < target {
					score++
				}
			}
		}
		if p.DownSegment != nil {
			if _, ok := used[p.DownSegment]; !ok {
				if downCount < target {
					score++
				}
			}
		}

		// Skip path if it cannot contribute new path segments for each types target amount
		if score == 0 {
			continue
		}

		add := func(s *seg.PathSegment, typ int) {
			if s == nil {
				return
			}
			if _, ok := used[s]; ok {
				return
			}

			used[s] = struct{}{}

			switch typ {
			case 0:
				up = append(up, s)
				upCount++
			case 1:
				core = append(core, s)
				coreCount++
			case 2:
				down = append(down, s)
				downCount++
			}
		}

		// Prefer adding segments that help balance first
		if p.UpSegment != nil && upCount < target {
			add(p.UpSegment, 0)
		}
		if p.CoreSegment != nil && coreCount < target {
			add(p.CoreSegment, 1)
		}
		if p.DownSegment != nil && downCount < target {
			add(p.DownSegment, 2)
		}
	}
	// now some segment types may have reached their target amount, but we might not have
	// reached the page size -> fill up with additional segments (if available)
	for i := 0; i < len(paths); i++ {
		idx := (start + i) % len(paths)
		p := paths[idx]
		if upCount+coreCount+downCount >= pageSize {
			break
		}

		tryAdd := func(s *seg.PathSegment, typ int) {
			if s == nil {
				return
			}
			if _, ok := used[s]; ok {
				return
			}

			used[s] = struct{}{}

			switch typ {
			case 0:
				up = append(up, s)
				upCount++
			case 1:
				core = append(core, s)
				coreCount++
			case 2:
				down = append(down, s)
				downCount++
			}
		}

		if p.UpSegment != nil {
			tryAdd(p.UpSegment, 0)
		}
		if upCount+coreCount+downCount >= pageSize {
			break
		}

		if p.CoreSegment != nil {
			tryAdd(p.CoreSegment, 1)
		}
		if upCount+coreCount+downCount >= pageSize {
			break
		}

		if p.DownSegment != nil {
			tryAdd(p.DownSegment, 2)
		}
	}
	return up, core, down, pagination + 1
}
