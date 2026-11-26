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

package segreq

import (
	"context"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/endhost"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/pagination"
)

// MaxSegmentsPageSize is the maximum (and default) number of segments returned per page.
const MaxSegmentsPageSize = 64

// PathFetcher returns all paths for the request.
type PathFetcher func(ctx context.Context) (SortedPaths, error)

// PageSegments returns one page of path segments for the given request.
//
// Every page contains at most page_size segments, and within a page all
// segments are unique. Segments may repeat over different pages.
// Every page, including the last one, contains the segments to construct at
// least one full path, if valid paths exist. Every path is fully contained in
// at least one page. Paths are processed in the order of the SortedPaths,
// i.e., shortest paths first.
//
// The page size and page token are validated before the paths are fetched.
//
// The page token is a cursor holding the sort key of the first path of the
// next page. If the paths are recomputed while a client is paginating, the
// client continues at the same path. Paths that are added in the meantime may
// or may not be included.
//
// Invalid page sizes and page tokens result in errors wrapping
// pagination.ErrInvalidPageSize and pagination.ErrInvalidPageToken. This
// includes a page size that is too small to hold the next path.
func PageSegments(
	ctx context.Context,
	req *endhost.ListSegmentsRequest,
	fetch PathFetcher,
) (*endhost.ListSegmentsResponse, error) {

	pageSize, err := pagination.PageSize(req.PageSize, MaxSegmentsPageSize)
	if err != nil {
		return nil, err
	}
	reqHash := segmentsRequestHash(req)
	cursor, err := pagination.DecodeToken(req.PageToken, reqHash)
	if err != nil {
		return nil, err
	}
	paths, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	start := 0
	if cursor != nil {
		start = paths.search(cursor)
	}

	up, core, down, next := getPage(paths.paths, pageSize, start)
	if next == start {
		return nil, serrors.JoinNoStack(pagination.ErrInvalidPageSize, nil,
			"reason", "page size too small to hold the next path",
			"page_size", pageSize, "path_segments", segmentCount(paths.paths[start]))
	}
	rep := &endhost.ListSegmentsResponse{
		UpSegments:   make([]*cppb.PathSegment, 0, len(up)),
		CoreSegments: make([]*cppb.PathSegment, 0, len(core)),
		DownSegments: make([]*cppb.PathSegment, 0, len(down)),
	}
	for _, s := range up {
		rep.UpSegments = append(rep.UpSegments, seg.PathSegmentToPB(s))
	}
	for _, s := range core {
		rep.CoreSegments = append(rep.CoreSegments, seg.PathSegmentToPB(s))
	}
	for _, s := range down {
		rep.DownSegments = append(rep.DownSegments, seg.PathSegmentToPB(s))
	}
	if next >= 0 {
		rep.NextPageToken = pagination.EncodeToken(reqHash, paths.keys[next])
	}
	return rep, nil
}

// segmentsRequestHash hashes all request parameters except for the page size
// and the page token.
func segmentsRequestHash(req *endhost.ListSegmentsRequest) []byte {
	h := pagination.NewRequestHasher()
	h.Uint64(uint64(addr.IA(req.SrcIsdAs)))
	h.Uint64(uint64(addr.IA(req.DstIsdAs)))
	return h.Sum()
}

func segmentCount(p CombinedPath) int {
	n := 0
	for _, s := range []*seg.PathSegment{p.UpSegment, p.CoreSegment, p.DownSegment} {
		if s != nil {
			n++
		}
	}
	return n
}

// getPage takes the sorted paths, the page size and the index of the first
// path of the page. It returns up to 'pageSize' path segments and the index of
// the first path of the next page, or -1 if this is the last page.
// All paths in paths[start:next] are fully contained in the page. If the page
// is not the last one and next == start, the page size is too small to hold
// paths[start].
func getPage(paths []CombinedPath, pageSize int, start int) (
	[]*seg.PathSegment, []*seg.PathSegment, []*seg.PathSegment, int) {

	up := []*seg.PathSegment{}
	core := []*seg.PathSegment{}
	down := []*seg.PathSegment{}

	target := pageSize / 3
	upCount, coreCount, downCount := 0, 0, 0
	used := make(map[*seg.PathSegment]struct{})

	i := start
	for ; i < len(paths); i++ {
		p := paths[i]
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
	partialPath := false
	// We have now included the path segments for at least the paths paths[start : start+target].
	// Now fill up the page with segments of additional paths.
	for i = start + target; i < len(paths); i++ {
		p := paths[i]
		if upCount+coreCount+downCount >= pageSize {
			break
		}

		tryAdd := func(s *seg.PathSegment, typ int) bool {
			if s == nil {
				return false
			}
			if _, ok := used[s]; ok {
				return true
			}
			if upCount+coreCount+downCount >= pageSize {
				return false
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
			return true
		}

		if p.UpSegment != nil {
			tryAdd(p.UpSegment, 0)
		}
		if p.CoreSegment != nil {
			if !tryAdd(p.CoreSegment, 1) {
				partialPath = true
				break
			}
		}
		if p.DownSegment != nil {
			if !tryAdd(p.DownSegment, 2) {
				partialPath = true
				break
			}
		}
	}
	if len(up)+len(core)+len(down) < pageSize || (i == len(paths) && !partialPath) {
		// we have reached the last page (i.e. together with the current page,
		// the endhost should have received all path segments)
		return up, core, down, -1
	}
	return up, core, down, i
}
