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
	"github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/proto/endhost/v1/endhostconnect"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
)

type PathService struct {
	url       string
	PageSize  int32
	PageToken string
}

func NewPathService(url string) *PathService {
	p := &PathService{
		url: url,
	}
	return p
}

func (s *PathService) Paths(ctx context.Context, dst, src addr.IA) ([]snet.Path, error) {
	if s.PageSize == 0 {
		s.PageSize = 64
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	client := endhostconnect.NewPathServiceClient(httpClient, s.url)
	res, err := client.ListSegments(ctx, &connect.Request[endhost.ListSegmentsRequest]{
		Msg: &endhost.ListSegmentsRequest{
			SrcIsdAs:  uint64(src),
			DstIsdAs:  uint64(dst),
			PageSize:  s.PageSize,
			PageToken: s.PageToken,
		},
	})
	if err != nil {
		return nil, err
	}
	fmt.Println("up segments")
	for _, pb := range res.Msg.UpSegments {
		ps, err := seg.SegmentFromPB(pb)
		if err != nil {
			return nil, err
		}
		for _, entry := range ps.ASEntries {
			fmt.Printf("%s, ", entry.Local)
		}
		fmt.Println()
	}
	fmt.Println("core segments")
	for _, pb := range res.Msg.CoreSegments {
		ps, err := seg.SegmentFromPB(pb)
		if err != nil {
			return nil, err
		}
		for _, entry := range ps.ASEntries {
			fmt.Printf("%s, ", entry.Local)
		}
		fmt.Println()
	}
	fmt.Println("down segments")
	for _, pb := range res.Msg.DownSegments {
		ps, err := seg.SegmentFromPB(pb)
		if err != nil {
			return nil, err
		}
		for _, entry := range ps.ASEntries {
			fmt.Printf("%s, ", entry.Local)
		}
		fmt.Println()
	}
	return nil, nil
}
