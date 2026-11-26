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

package segreq_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/control/segreq"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/endhost"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/pagination"
)

// segFactory creates distinct segments. Each segment has a single AS entry with
// a unique ISD-AS, so all segments have the same length but different IDs. The
// segment is tagged in Info.Raw, which ends up in the SegmentInfo field of the
// protobuf, so that it can be identified in the response.
type segFactory struct{ n int }

func (f *segFactory) new() *seg.PathSegment {
	f.n++
	return &seg.PathSegment{
		Info:      seg.Info{Raw: []byte(fmt.Sprintf("seg-%d", f.n))},
		ASEntries: []seg.ASEntry{{Local: addr.MustIAFrom(1, addr.AS(f.n))}},
	}
}

// shape describes a path by the segment types it contains, e.g., "ucd".
func (f *segFactory) paths(n int, shape string) []segreq.CombinedPath {
	paths := make([]segreq.CombinedPath, 0, n)
	for range n {
		var p segreq.CombinedPath
		for _, c := range shape {
			switch c {
			case 'u':
				p.UpSegment = f.new()
			case 'c':
				p.CoreSegment = f.new()
			case 'd':
				p.DownSegment = f.new()
			}
		}
		paths = append(paths, p)
	}
	return paths
}

func fetcher(paths []segreq.CombinedPath) segreq.PathFetcher {
	sorted := segreq.SortPaths(paths)
	return func(context.Context) (segreq.SortedPaths, error) {
		return sorted, nil
	}
}

func request(pageSize int32) *endhost.ListSegmentsRequest {
	return &endhost.ListSegmentsRequest{
		SrcIsdAs: uint64(addr.MustIAFrom(1, 0xff00_0000_0110)),
		DstIsdAs: uint64(addr.MustIAFrom(2, 0xff00_0000_0220)),
		PageSize: pageSize,
	}
}

type counts [3]int // up, core, down

func tag(s *seg.PathSegment) string { return string(s.Info.Raw) }

func pbTags(segs []*cppb.PathSegment) []string {
	tags := make([]string, 0, len(segs))
	for _, s := range segs {
		tags = append(tags, string(s.SegmentInfo))
	}
	return tags
}

// paginate fetches all pages and checks the pagination invariants:
//   - a page contains at most page size segments,
//   - segments are unique within a page,
//   - every page contains at least one full path,
//   - every path is fully contained in at least one page.
//
// It returns the number of segments per type of each page.
func paginate(
	t *testing.T,
	req *endhost.ListSegmentsRequest,
	paths []segreq.CombinedPath,
	fetch segreq.PathFetcher,
) []counts {

	t.Helper()
	pageSize := int(req.PageSize)
	if pageSize == 0 || pageSize > segreq.MaxSegmentsPageSize {
		pageSize = segreq.MaxSegmentsPageSize
	}
	// The path covered by a page, expressed via segment tags per type.
	contains := func(page [3]map[string]bool, p segreq.CombinedPath) bool {
		for i, s := range []*seg.PathSegment{p.UpSegment, p.CoreSegment, p.DownSegment} {
			if s != nil && !page[i][tag(s)] {
				return false
			}
		}
		return true
	}

	var result []counts
	covered := make([]bool, len(paths))
	req.PageToken = ""
	for {
		rep, err := segreq.PageSegments(context.Background(), req, fetch)
		require.NoError(t, err)

		var page [3]map[string]bool
		for i, segs := range [][]*cppb.PathSegment{
			rep.UpSegments, rep.CoreSegments, rep.DownSegments,
		} {
			page[i] = map[string]bool{}
			for _, tg := range pbTags(segs) {
				require.False(t, page[i][tg], "segment %s repeated within page", tg)
				page[i][tg] = true
			}
		}
		total := len(rep.UpSegments) + len(rep.CoreSegments) + len(rep.DownSegments)
		require.LessOrEqual(t, total, pageSize)

		fullPaths := 0
		for i, p := range paths {
			if contains(page, p) {
				covered[i] = true
				fullPaths++
			}
		}
		if len(paths) > 0 {
			require.Positive(t, fullPaths, "page %d contains no full path", len(result))
		}
		result = append(result, counts{
			len(rep.UpSegments), len(rep.CoreSegments), len(rep.DownSegments),
		})
		if rep.NextPageToken == "" {
			break
		}
		require.Less(t, len(result), 1000, "pagination does not terminate")
		req.PageToken = rep.NextPageToken
	}
	for i, ok := range covered {
		assert.True(t, ok, "path %d is never fully contained in a page", i)
	}
	return result
}

func TestPageSegments(t *testing.T) {
	testCases := map[string]struct {
		pageSize int32
		paths    func(f *segFactory) []segreq.CombinedPath
		want     []counts
	}{
		"empty": {
			pageSize: 3,
			paths:    func(f *segFactory) []segreq.CombinedPath { return nil },
			want:     []counts{{0, 0, 0}},
		},
		"single up segment, single path": {
			pageSize: 2,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(1, "u") },
			want:     []counts{{1, 0, 0}},
		},
		"single up segment, many paths": {
			pageSize: 2,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(2, "u") },
			want:     []counts{{2, 0, 0}},
		},
		"single up segment, two pages": {
			pageSize: 2,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(3, "u") },
			want:     []counts{{2, 0, 0}, {1, 0, 0}},
		},
		"single up segment, page size one": {
			pageSize: 1,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(3, "u") },
			want:     []counts{{1, 0, 0}, {1, 0, 0}, {1, 0, 0}},
		},
		"single core segment, single path": {
			pageSize: 2,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(1, "c") },
			want:     []counts{{0, 1, 0}},
		},
		"single core segment, many paths": {
			pageSize: 2,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(2, "c") },
			want:     []counts{{0, 2, 0}},
		},
		"single core segment, two pages": {
			pageSize: 2,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(3, "c") },
			want:     []counts{{0, 2, 0}, {0, 1, 0}},
		},
		"single down segment, single path": {
			pageSize: 2,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(1, "d") },
			want:     []counts{{0, 0, 1}},
		},
		"single down segment, many paths": {
			pageSize: 2,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(2, "d") },
			want:     []counts{{0, 0, 2}},
		},
		"single down segment, two pages": {
			pageSize: 2,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(3, "d") },
			want:     []counts{{0, 0, 2}, {0, 0, 1}},
		},
		"two segments, page size 2": {
			pageSize: 2,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(3, "uc") },
			want:     []counts{{1, 1, 0}, {1, 1, 0}, {1, 1, 0}},
		},
		"two segments, page size 3": {
			pageSize: 3,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(3, "uc") },
			want:     []counts{{2, 1, 0}, {2, 1, 0}, {1, 1, 0}},
		},
		"two segments, up and down": {
			pageSize: 3,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(2, "ud") },
			want:     []counts{{2, 0, 1}, {1, 0, 1}},
		},
		"three segments, page size 6": {
			pageSize: 6,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(4, "ucd") },
			want:     []counts{{2, 2, 2}, {2, 2, 2}},
		},
		"three segments, page size 7": {
			pageSize: 7,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(4, "ucd") },
			want:     []counts{{3, 2, 2}, {2, 2, 2}},
		},
		"mixed number of segments": {
			pageSize: 5,
			paths: func(f *segFactory) []segreq.CombinedPath {
				// The up-down path is shorter and therefore comes first,
				// regardless of the input order.
				return append(f.paths(3, "ucd"), f.paths(1, "ud")...)
			},
			want: []counts{{2, 1, 2}, {2, 2, 1}, {1, 1, 1}},
		},
		"shared segments, two pages": {
			pageSize: 5,
			paths: func(f *segFactory) []segreq.CombinedPath {
				return sharedUpDown(f, 4)
			},
			want: []counts{{1, 3, 1}, {1, 1, 1}},
		},
		"shared segments, single page": {
			pageSize: 5,
			paths: func(f *segFactory) []segreq.CombinedPath {
				return sharedUpDown(f, 3)
			},
			want: []counts{{1, 3, 1}},
		},
		"default page size": {
			pageSize: 0,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(100, "u") },
			want:     []counts{{64, 0, 0}, {36, 0, 0}},
		},
		"page size larger than max": {
			pageSize: 1000,
			paths:    func(f *segFactory) []segreq.CombinedPath { return f.paths(100, "u") },
			want:     []counts{{64, 0, 0}, {36, 0, 0}},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			paths := tc.paths(&segFactory{})
			got := paginate(t, request(tc.pageSize), paths, fetcher(paths))
			assert.Equal(t, tc.want, got)
		})
	}
}

func sharedUpDown(f *segFactory, n int) []segreq.CombinedPath {
	up, down := f.new(), f.new()
	paths := make([]segreq.CombinedPath, 0, n)
	for range n {
		paths = append(paths, segreq.CombinedPath{
			UpSegment:   up,
			CoreSegment: f.new(),
			DownSegment: down,
		})
	}
	return paths
}

// TestPageSegmentsInvariants checks the pagination invariants for many
// combinations of page sizes and paths with shared segments.
func TestPageSegmentsInvariants(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 50 {
		f := &segFactory{}
		ups := []*seg.PathSegment{f.new(), f.new(), f.new()}
		cores := []*seg.PathSegment{f.new(), f.new(), f.new(), f.new()}
		downs := []*seg.PathSegment{f.new(), f.new(), f.new()}
		pick := func(s []*seg.PathSegment) *seg.PathSegment { return s[r.IntN(len(s))] }

		var paths []segreq.CombinedPath
		for range 1 + r.IntN(30) {
			var p segreq.CombinedPath
			switch r.IntN(4) {
			case 0:
				p = segreq.CombinedPath{UpSegment: pick(ups), CoreSegment: pick(cores),
					DownSegment: pick(downs)}
			case 1:
				p = segreq.CombinedPath{UpSegment: pick(ups), CoreSegment: pick(cores)}
			case 2:
				p = segreq.CombinedPath{CoreSegment: pick(cores), DownSegment: pick(downs)}
			case 3:
				p = segreq.CombinedPath{UpSegment: pick(ups), DownSegment: pick(downs)}
			}
			paths = append(paths, p)
		}
		for pageSize := int32(3); pageSize <= 12; pageSize++ {
			t.Run(fmt.Sprintf("set %d page size %d", i, pageSize), func(t *testing.T) {
				paginate(t, request(pageSize), paths, fetcher(paths))
			})
		}
	}
}

func TestPageSegmentsDeduplicates(t *testing.T) {
	f := &segFactory{}
	p := f.paths(1, "ucd")[0]
	// A path with different segment objects that have the same IDs.
	clone := segreq.CombinedPath{
		UpSegment:   &seg.PathSegment{ASEntries: p.UpSegment.ASEntries},
		CoreSegment: &seg.PathSegment{ASEntries: p.CoreSegment.ASEntries},
		DownSegment: &seg.PathSegment{ASEntries: p.DownSegment.ASEntries},
	}
	sorted := segreq.SortPaths([]segreq.CombinedPath{p, p, clone})
	assert.Equal(t, 1, sorted.Len())
}

func TestPageSegmentsOrderIndependent(t *testing.T) {
	f := &segFactory{}
	paths := append(f.paths(5, "ucd"), f.paths(5, "uc")...)
	paths = append(paths, f.paths(5, "u")...)
	want := segreq.SortPaths(paths).Paths()

	shuffled := append([]segreq.CombinedPath(nil), paths...)
	rand.New(rand.NewPCG(3, 4)).Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	got := segreq.SortPaths(shuffled).Paths()
	assert.Equal(t, want, got)
	for i := 1; i < len(got); i++ {
		assert.LessOrEqual(t, got[i-1].Length(), got[i].Length())
	}
}

// TestPageSegmentsRecomputedPaths checks that a client continues at the right
// path if the paths are recomputed (in a different order and with additional
// paths) while paginating.
func TestPageSegmentsRecomputedPaths(t *testing.T) {
	f := &segFactory{}
	paths := f.paths(10, "ucd")
	req := request(6)

	rep, err := segreq.PageSegments(context.Background(), req, fetcher(paths))
	require.NoError(t, err)
	require.NotEmpty(t, rep.NextPageToken)
	seen := map[string]bool{}
	for _, tg := range pbTags(rep.CoreSegments) {
		seen[tg] = true
	}

	recomputed := append(f.paths(5, "ucd"), paths...)
	for i, j := 0, len(recomputed)-1; i < j; i, j = i+1, j-1 {
		recomputed[i], recomputed[j] = recomputed[j], recomputed[i]
	}
	fetch := fetcher(recomputed)
	for req.PageToken = rep.NextPageToken; req.PageToken != ""; {
		rep, err = segreq.PageSegments(context.Background(), req, fetch)
		require.NoError(t, err)
		for _, tg := range pbTags(rep.CoreSegments) {
			seen[tg] = true
		}
		req.PageToken = rep.NextPageToken
	}
	// All paths are "ucd" with distinct segments, so a path was received if its
	// core segment was received.
	for _, p := range paths {
		assert.True(t, seen[tag(p.CoreSegment)], "path with core %s missing", tag(p.CoreSegment))
	}
}

func TestPageSegmentsInvalidInput(t *testing.T) {
	f := &segFactory{}
	paths := f.paths(4, "ucd")
	firstToken := func(t *testing.T) string {
		rep, err := segreq.PageSegments(context.Background(), request(6), fetcher(paths))
		require.NoError(t, err)
		require.NotEmpty(t, rep.NextPageToken)
		return rep.NextPageToken
	}
	mustNotFetch := func(t *testing.T) segreq.PathFetcher {
		return func(context.Context) (segreq.SortedPaths, error) {
			t.Fatal("paths must not be fetched for invalid requests")
			return segreq.SortedPaths{}, nil
		}
	}

	t.Run("negative page size", func(t *testing.T) {
		_, err := segreq.PageSegments(context.Background(), request(-1), mustNotFetch(t))
		assert.ErrorIs(t, err, pagination.ErrInvalidPageSize)
	})
	t.Run("page size too small for path", func(t *testing.T) {
		_, err := segreq.PageSegments(context.Background(), request(2), fetcher(paths))
		assert.ErrorIs(t, err, pagination.ErrInvalidPageSize)
	})
	t.Run("garbage token", func(t *testing.T) {
		req := request(6)
		req.PageToken = "not a token!"
		_, err := segreq.PageSegments(context.Background(), req, mustNotFetch(t))
		assert.ErrorIs(t, err, pagination.ErrInvalidPageToken)
	})
	t.Run("legacy index token", func(t *testing.T) {
		req := request(6)
		req.PageToken = "2"
		_, err := segreq.PageSegments(context.Background(), req, mustNotFetch(t))
		assert.ErrorIs(t, err, pagination.ErrInvalidPageToken)
	})
	t.Run("changed destination", func(t *testing.T) {
		req := request(6)
		req.PageToken = firstToken(t)
		req.DstIsdAs = uint64(addr.MustIAFrom(3, 0xff00_0000_0330))
		_, err := segreq.PageSegments(context.Background(), req, mustNotFetch(t))
		assert.ErrorIs(t, err, pagination.ErrInvalidPageToken)
	})
	t.Run("changed page size is allowed", func(t *testing.T) {
		req := request(9)
		req.PageToken = firstToken(t)
		_, err := segreq.PageSegments(context.Background(), req, fetcher(paths))
		assert.NoError(t, err)
	})
	t.Run("fetch error is returned", func(t *testing.T) {
		fetchErr := fmt.Errorf("lookup failed")
		_, err := segreq.PageSegments(context.Background(), request(6),
			func(context.Context) (segreq.SortedPaths, error) {
				return segreq.SortedPaths{}, fetchErr
			})
		assert.ErrorIs(t, err, fetchErr)
	})
}
