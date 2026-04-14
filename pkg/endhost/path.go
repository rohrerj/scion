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
	"crypto/tls"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/proto/endhost/v1/endhostconnect"
	seg "github.com/scionproto/scion/pkg/segment"
)

type PathService struct {
	url          string
	httpClient   *http.Client
	PageSize     int32
	trustService *TrustService
}

func NewPathService(url string, trustService *TrustService) *PathService {
	p := &PathService{
		url: url,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		trustService: trustService,
	}
	return p
}

type Paginator struct {
	url          string
	httpClient   *http.Client
	pageSize     int32
	pageToken    string
	src          addr.IA
	dst          addr.IA
	trustService *TrustService
}

func (s *PathService) NewPaginator(dst, src addr.IA) *Paginator {
	return &Paginator{
		url:          s.url,
		httpClient:   s.httpClient,
		pageSize:     s.PageSize,
		pageToken:    "",
		src:          src,
		dst:          dst,
		trustService: s.trustService,
	}
}

func (s *Paginator) NextPage(ctx context.Context) ([]*seg.PathSegment, []*seg.PathSegment, []*seg.PathSegment, error) {
	client := endhostconnect.NewPathServiceClient(s.httpClient, s.url)
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

	upSegments := make([]*seg.PathSegment, 0, len(res.Msg.UpSegments))
	coreSegments := make([]*seg.PathSegment, 0, len(res.Msg.CoreSegments))
	downSegments := make([]*seg.PathSegment, 0, len(res.Msg.DownSegments))
	for _, pb := range res.Msg.UpSegments {
		ps, err := seg.SegmentFromPB(pb)
		if err != nil {
			return nil, nil, nil, err
		}
		err = s.trustService.VerifyPathSegment(ctx, ps)
		if err != nil {
			fmt.Println("1verification failed")
			return nil, nil, nil, err
		}
		fmt.Println("verification passed")
		upSegments = append(upSegments, ps)
	}
	for _, pb := range res.Msg.CoreSegments {
		ps, err := seg.SegmentFromPB(pb)
		if err != nil {
			return nil, nil, nil, err
		}
		err = s.trustService.VerifyPathSegment(ctx, ps)
		if err != nil {
			fmt.Println("2verification failed")
			return nil, nil, nil, err
		}
		fmt.Println("verification passed")
		coreSegments = append(coreSegments, ps)
	}
	for _, pb := range res.Msg.DownSegments {
		ps, err := seg.SegmentFromPB(pb)
		if err != nil {
			return nil, nil, nil, err
		}
		err = s.trustService.VerifyPathSegment(ctx, ps)
		if err != nil {
			fmt.Println("3verification failed")
			return nil, nil, nil, err
		}
		fmt.Println("verification passed")
		downSegments = append(downSegments, ps)
	}
	return upSegments, coreSegments, downSegments, nil
}
