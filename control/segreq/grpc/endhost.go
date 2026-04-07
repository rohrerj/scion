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
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/scionproto/scion/control/segreq"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	ehpb "github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/segment"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/path/combinator"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/trust"
)

// LookupServer handles path segment lookups.
type EndhostServer struct {
	Lookuper Lookuper
	RevCache revcache.RevCache

	// Requests aggregates all the incoming requests received by the handler.
	// If it is not initialized, nothing is reported.
	Requests metrics.Counter
	// SegmentsSent aggregates the number of segments that were transmitted in
	// response to a segment request.
	SegmentsSent metrics.Counter
	LocalIA      addr.IA
	IsCore       bool
	Inspector    trust.Inspector
	PathDB       pathdb.DB
}

func (s EndhostServer) ListSegments(ctx context.Context,
	req *ehpb.ListSegmentsRequest) (*ehpb.ListSegmentsResponse, error) {

	src, dst := addr.IA(req.SrcIsdAs), addr.IA(req.DstIsdAs)
	logger := log.FromCtx(ctx)
	span := opentracing.SpanFromContext(ctx)
	setQueryTags(span, src, dst)
	logger.Debug("Received ListSegments request", "src", src, "dst", dst)
	splitter := segreq.NewSplitter(s.LocalIA, s.IsCore, s.Inspector, s.PathDB)
	reqs, err := splitter.Split(ctx, dst)
	if err != nil {
		return nil, err
	}
	res := &ehpb.ListSegmentsResponse{}
	upSegments := make(seg.Segments, 0, 1)
	coreSegments := make(seg.Segments, 0, 1)
	downSegments := make(seg.Segments, 0, 1)
	log.Debug("ListSegments", "reqs srcIAs", reqs.SrcIAs(), "reqs dstIAs", reqs.DstIAs())
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
	//paths := s.buildAllPaths(src, dst, upSegments, coreSegments, downSegments)
	sort.Slice(upSegments, func(i, j int) bool {
		return len(upSegments[i].ASEntries) < len(upSegments[j].ASEntries)
	})
	sort.Slice(coreSegments, func(i, j int) bool {
		return len(coreSegments[i].ASEntries) < len(coreSegments[j].ASEntries)
	})
	sort.Slice(downSegments, func(i, j int) bool {
		return len(downSegments[i].ASEntries) < len(downSegments[j].ASEntries)
	})

	// select roughly req.PageSize/3 up, core, and down segments
	numSegmentsToInclude := int(req.PageSize)
	numUpSegmentsToInclude := numSegmentsToInclude / 3
	if numUpSegmentsToInclude > len(upSegments) {
		numUpSegmentsToInclude = len(upSegments)
	}
	numSegmentsToInclude -= numUpSegmentsToInclude

	numCoreSegmentsToInclude := numSegmentsToInclude / 2
	if numCoreSegmentsToInclude > len(coreSegments) {
		numCoreSegmentsToInclude = len(coreSegments)
	}
	numSegmentsToInclude -= numCoreSegmentsToInclude

	numDownSegmentsToInclude := numSegmentsToInclude
	if numDownSegmentsToInclude > len(downSegments) {
		numDownSegmentsToInclude = len(downSegments)
	}
	numSegmentsToInclude -= numDownSegmentsToInclude

	if numSegmentsToInclude > 0 {
		remainingCapacity := len(coreSegments) - numCoreSegmentsToInclude
		extra := min(remainingCapacity, numSegmentsToInclude)
		numCoreSegmentsToInclude += extra
		numSegmentsToInclude -= extra
	}

	if numSegmentsToInclude > 0 {
		remainingCapacity := len(upSegments) - numUpSegmentsToInclude
		extra := min(remainingCapacity, numSegmentsToInclude)
		numUpSegmentsToInclude += extra
		numSegmentsToInclude -= extra
	}

	if numSegmentsToInclude > 0 {
		remainingCapacity := len(downSegments) - numDownSegmentsToInclude
		extra := min(remainingCapacity, numSegmentsToInclude)
		numDownSegmentsToInclude += extra
		numSegmentsToInclude -= extra
	}
	for i := 0; i < numUpSegmentsToInclude; i++ {
		res.UpSegments = append(res.UpSegments, seg.PathSegmentToPB(upSegments[i]))
	}
	for i := 0; i < numCoreSegmentsToInclude; i++ {
		res.CoreSegments = append(res.CoreSegments, seg.PathSegmentToPB(coreSegments[i]))
	}
	for i := 0; i < numDownSegmentsToInclude; i++ {
		res.DownSegments = append(res.DownSegments, seg.PathSegmentToPB(downSegments[i]))
	}

	logger.Debug("Replied with segments", "core", len(res.CoreSegments), "up", len(res.UpSegments), "down", len(res.DownSegments))
	return res, nil
}

func (s EndhostServer) buildAllPaths(src, dst addr.IA, up, core, down seg.Segments) []combinator.Path {
	destinations := s.findDestinations(dst, up, core)
	var paths []combinator.Path
	for dst := range destinations {
		paths = append(paths, combinator.Combine(src, dst, up, core, down, false)...)
	}
	// Filter expired paths
	now := time.Now()
	var validPaths []combinator.Path
	for _, path := range paths {
		if path.Metadata.Expiry.After(now) {
			validPaths = append(validPaths, path)
		}
	}
	return validPaths
}

func (s EndhostServer) findDestinations(dst addr.IA, ups, cores seg.Segments) map[addr.IA]struct{} {
	if !dst.IsWildcard() {
		return map[addr.IA]struct{}{dst: {}}
	}
	all := cores.FirstIAs()
	if dst.ISD() == s.LocalIA.ISD() {
		// for isd local wildcard we want to reach cores, they are at the end of the up segs.
		all = append(all, ups.FirstIAs()...)
	}
	destinations := make(map[addr.IA]struct{})
	for _, dst := range all {
		destinations[dst] = struct{}{}
	}
	return destinations
}
