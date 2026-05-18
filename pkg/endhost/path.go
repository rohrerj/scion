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

package endhost

import (
	"context"
	"net"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/proto/endhost/v1/endhostconnect"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/path/combinator"
)

type PathService struct {
	url                     string
	httpClient              *http.Client
	trustService            *TrustService
	topo                    snet.Topology
	verificationUnsupported bool
	token                   string
}

func (c *Connector) NewPathService() *PathService {
	p := &PathService{
		url:          c.api,
		topo:         c.Topology,
		httpClient:   c.httpClient,
		trustService: c.TrustService,
		token:        c.token,
	}
	return p
}

type PathReqOption func(*pathReqOptions)
type pathReqOptions struct {
	verifyPathSegments                     bool
	numPaths                               uint32
	skipSegmentVerificationIfUnimplemented bool
}

// WithVerifyPathSegments filters out all path segments for which
// verification fails.
func WithVerifyPathSegments() PathReqOption {
	return func(o *pathReqOptions) {
		o.verifyPathSegments = true
	}
}

// WithNumberOfPaths sets the maximum number of paths to return.
// If the limit is not reached after requesting a page, further
// pages are requested. Setting this option to 0 ensures
// that all paths are returned.
func WithNumberOfPaths(n uint32) PathReqOption {
	return func(o *pathReqOptions) {
		o.numPaths = n
	}
}

func WithSkipSegmentVerificationIfUnsupportedByAS() PathReqOption {
	return func(o *pathReqOptions) {
		o.skipSegmentVerificationIfUnimplemented = true
	}
}

func (s *PathService) filterVerifiedSegments(ctx context.Context, up []*seg.PathSegment,
	core []*seg.PathSegment, down []*seg.PathSegment, options *pathReqOptions) (
	[]*seg.PathSegment, []*seg.PathSegment, []*seg.PathSegment, error) {

	verify := func(segments []*seg.PathSegment) ([]*seg.PathSegment, error) {
		if len(segments) == 0 {
			return segments, nil
		}
		verifiedSegments := make([]*seg.PathSegment, 0, len(segments))
		verificationErrors, err := s.trustService.VerifyPathSegments(ctx, segments)
		if err != nil {
			return nil, err
		}
		for i := range verificationErrors {
			if verificationErrors[i] != nil {
				log.Debug("Path segment filtered", "firstIA", segments[i].FirstIA(),
					"lastIA", segments[i].LastIA(), "err", verificationErrors[i])
			} else {
				verifiedSegments = append(verifiedSegments, segments[i])
			}
		}
		return verifiedSegments, nil
	}
	if s.trustService == nil {
		return nil, nil, nil, serrors.New("trust service not configured")
	}

	verifiedUp, err := verify(up)
	if err != nil {

		if connect.CodeOf(err) == connect.CodeUnimplemented || connect.CodeOf(err) == connect.CodeUnavailable {
			s.verificationUnsupported = true
		} else {
			return nil, nil, nil, err
		}
	}
	verifiedCore, err := verify(core)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnimplemented || connect.CodeOf(err) == connect.CodeUnavailable {
			s.verificationUnsupported = true
		} else {
			return nil, nil, nil, err
		}
	}
	verifiedDown, err := verify(down)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnimplemented || connect.CodeOf(err) == connect.CodeUnavailable {
			s.verificationUnsupported = true
		} else {
			return nil, nil, nil, err
		}
	}
	if s.verificationUnsupported {
		log.Debug("requested segment verification but unsupported by local AS")
		if options.skipSegmentVerificationIfUnimplemented {
			return up, core, down, nil
		} else {
			return up, core, down,
				serrors.New("requested segment verification but unsupported by local AS")
		}
	}
	return verifiedUp, verifiedCore, verifiedDown, nil
}

// Paths returns all paths from the src IA to the dst IA.
// It asks for the corresponding path segments from the endhost API endpoint and combines them
// into end to end paths. The maximum number of paths returned can be configured via the
// WithNumberOfPaths options. Additionally, the VerifyPathSegments option can be used to filter
// out all path segments that fail verification.
func (s *PathService) Paths(ctx context.Context, dst addr.IA, src addr.IA, opts ...PathReqOption) (
	[]snet.Path, error) {

	interfacesToString := func(elems []snet.PathInterface) string {
		parts := make([]string, len(elems))
		for i, e := range elems {
			parts[i] = e.String()
		}
		return strings.Join(parts, "|")
	}
	options := &pathReqOptions{}
	for _, opt := range opts {
		opt(options)
	}
	maxRequestedPaths := uint32(1)
	if options.numPaths != 0 {
		maxRequestedPaths = options.numPaths
	}
	paginator := s.NewPaginator(dst, src, 64, s.token)
	paths := make([]snet.Path, 0, 64)
	seen := make(map[string]struct{})

	for len(paths) < int(maxRequestedPaths) && paginator.HasNext() {
		up, core, down, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if options.verifyPathSegments && !s.verificationUnsupported {
			up, core, down, err = s.filterVerifiedSegments(ctx, up, core, down, options)
			if err != nil {
				return nil, err
			}
		}
		combinedPaths := combinator.Combine(src, dst, up, core, down, false)
		for _, p := range combinedPaths {
			mapKey := interfacesToString(p.Metadata.Interfaces)
			if _, isSeen := seen[mapKey]; isSeen {
				continue
			}
			path := snetpath.Path{
				Src:           src,
				Dst:           dst,
				DataplanePath: p.SCIONPath,
				Meta:          p.Metadata,
			}
			nextHopNetIpPort, ok := s.topo.Interface(uint16(p.Metadata.Interfaces[0].ID))
			if ok {
				addr := nextHopNetIpPort.Addr()
				nextHop := &net.UDPAddr{
					IP:   addr.AsSlice(),
					Port: int(nextHopNetIpPort.Port()),
					Zone: addr.Zone(),
				}
				path.NextHop = nextHop
			}

			paths = append(paths, path)
			seen[mapKey] = struct{}{}
		}
	}
	if options.numPaths != 0 && len(paths) > int(options.numPaths) {
		return paths[:options.numPaths], nil
	}
	return paths, nil
}

type Paginator struct {
	url          string
	httpClient   *http.Client
	pageSize     int32
	pageToken    string
	hasNext      bool
	src          addr.IA
	dst          addr.IA
	trustService *TrustService
	token        string
}

func (s *PathService) NewPaginator(dst, src addr.IA, pageSize int32, jwtToken string) *Paginator {
	return &Paginator{
		url:          s.url,
		httpClient:   s.httpClient,
		pageSize:     pageSize,
		pageToken:    "",
		hasNext:      true,
		src:          src,
		dst:          dst,
		trustService: s.trustService,
		token:        jwtToken,
	}
}

func (s *Paginator) HasNext() bool {
	return s.hasNext
}

func (s *Paginator) NextPage(ctx context.Context) (
	[]*seg.PathSegment, []*seg.PathSegment, []*seg.PathSegment, error) {

	client := endhostconnect.NewSegmentsServiceClient(s.httpClient, s.url, connect.WithInterceptors(authInterceptor(s.token)))
	res, err := client.ListSegments(ctx, &connect.Request[endhost.ListSegmentsRequest]{
		Msg: &endhost.ListSegmentsRequest{
			SrcIsdAs:  uint64(s.src),
			DstIsdAs:  uint64(s.dst),
			PageSize:  s.pageSize,
			PageToken: s.pageToken,
		},
	})
	if err != nil {
		return nil, nil, nil, serrors.Wrap("on ListSegments", err)
	}
	s.pageToken = res.Msg.NextPageToken
	s.hasNext = s.pageToken != ""

	upSegments := make([]*seg.PathSegment, 0, len(res.Msg.UpSegments))
	coreSegments := make([]*seg.PathSegment, 0, len(res.Msg.CoreSegments))
	downSegments := make([]*seg.PathSegment, 0, len(res.Msg.DownSegments))
	for _, pb := range res.Msg.UpSegments {
		ps, err := seg.SegmentFromPB(pb)
		if err != nil {
			return nil, nil, nil, err
		}
		upSegments = append(upSegments, ps)
	}
	for _, pb := range res.Msg.CoreSegments {
		ps, err := seg.SegmentFromPB(pb)
		if err != nil {
			return nil, nil, nil, err
		}
		coreSegments = append(coreSegments, ps)
	}
	for _, pb := range res.Msg.DownSegments {
		ps, err := seg.SegmentFromPB(pb)
		if err != nil {
			return nil, nil, nil, err
		}
		downSegments = append(downSegments, ps)
	}
	return upSegments, coreSegments, downSegments, nil
}
