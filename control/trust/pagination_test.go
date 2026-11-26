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

package trust_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/control/trust"
	"github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/private/pagination"
)

func fakeChain(name string) []*x509.Certificate {
	return []*x509.Certificate{
		{Raw: []byte("as-" + name)},
		{Raw: []byte("ca-" + name)},
	}
}

func fakeChains(prefix string, n int) [][]*x509.Certificate {
	chains := make([][]*x509.Certificate, 0, n)
	for i := range n {
		chains = append(chains, fakeChain(fmt.Sprintf("%s-%d", prefix, i)))
	}
	return chains
}

// store maps subject index to chains, and records which subjects were fetched.
type store struct {
	chains  map[int][][]*x509.Certificate
	fetched []int
}

func (s *store) fetch(_ context.Context, idx int) ([][]*x509.Certificate, error) {
	s.fetched = append(s.fetched, idx)
	// Return a reversed copy to make sure the paginator does not rely on the
	// order returned by the provider.
	in := s.chains[idx]
	out := make([][]*x509.Certificate, len(in))
	for i, c := range in {
		out[len(in)-1-i] = c
	}
	return out, nil
}

func newRequest(subjects int, pageSize int32) *endhost.ListChainsRequest {
	req := &endhost.ListChainsRequest{PageSize: pageSize, AtLeastValidUntil: 42}
	for i := range subjects {
		req.Subjects = append(req.Subjects, &endhost.Subject{
			IsdAs:        uint64(i + 1),
			SubjectKeyId: []byte{byte(i)},
		})
	}
	return req
}

func chainKey(c *endhost.Chain) string {
	return string(c.AsCert) + "|" + string(c.CaCert)
}

// collectAll pages through all results and returns the chain keys and the
// number of pages.
func collectAll(t *testing.T, req *endhost.ListChainsRequest, s *store) ([]string, int) {
	t.Helper()
	var keys []string
	pages := 0
	req.PageToken = ""
	for {
		rep, err := trust.PageChains(context.Background(), req, s.fetch)
		require.NoError(t, err)
		pages++
		pageSize := int(req.PageSize)
		if pageSize == 0 || pageSize > trust.MaxChainsPageSize {
			pageSize = trust.MaxChainsPageSize
		}
		require.LessOrEqual(t, len(rep.Chains), pageSize)
		for _, c := range rep.Chains {
			keys = append(keys, chainKey(c))
		}
		if rep.NextPageToken == "" {
			return keys, pages
		}
		require.Less(t, pages, 1000, "pagination does not terminate")
		req.PageToken = rep.NextPageToken
	}
}

func TestPageChainsCompleteAndUnique(t *testing.T) {
	testCases := map[string]struct {
		perSubject []int
		pageSize   int32
	}{
		"empty request":              {perSubject: nil, pageSize: 3},
		"single page":                {perSubject: []int{2, 1}, pageSize: 10},
		"page size one":              {perSubject: []int{3, 0, 2}, pageSize: 1},
		"exact subject boundary":     {perSubject: []int{3, 3, 3}, pageSize: 3},
		"spans subjects":             {perSubject: []int{5, 4, 7}, pageSize: 4},
		"empty subjects in between":  {perSubject: []int{0, 2, 0, 0, 3, 0}, pageSize: 2},
		"default page size":          {perSubject: []int{100, 50}, pageSize: 0},
		"page size larger than max":  {perSubject: []int{100}, pageSize: 1000},
		"trailing subjects no chain": {perSubject: []int{2, 0, 0}, pageSize: 2},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			s := &store{chains: map[int][][]*x509.Certificate{}}
			var want []string
			for i, n := range tc.perSubject {
				s.chains[i] = fakeChains(fmt.Sprintf("s%d", i), n)
				for _, c := range s.chains[i] {
					want = append(want, string(c[0].Raw)+"|"+string(c[1].Raw))
				}
			}
			req := newRequest(len(tc.perSubject), tc.pageSize)
			got, _ := collectAll(t, req, s)
			assert.ElementsMatch(t, want, got)
		})
	}
}

func TestPageChainsSubjectFieldAndOrder(t *testing.T) {
	s := &store{chains: map[int][][]*x509.Certificate{
		0: fakeChains("a", 2),
		1: fakeChains("b", 2),
	}}
	req := newRequest(2, 0)
	rep, err := trust.PageChains(context.Background(), req, s.fetch)
	require.NoError(t, err)
	require.Len(t, rep.Chains, 4)
	assert.Empty(t, rep.NextPageToken)
	assert.Equal(t, req.Subjects[0], rep.Chains[0].Subject)
	assert.Equal(t, req.Subjects[0], rep.Chains[1].Subject)
	assert.Equal(t, req.Subjects[1], rep.Chains[2].Subject)
	assert.Equal(t, req.Subjects[1], rep.Chains[3].Subject)
}

func TestPageChainsDeduplicates(t *testing.T) {
	c := fakeChain("dup")
	s := &store{chains: map[int][][]*x509.Certificate{0: {c, c, fakeChain("other")}}}
	got, _ := collectAll(t, newRequest(1, 1), s)
	assert.Len(t, got, 2)
}

func TestPageChainsFetchesLazily(t *testing.T) {
	s := &store{chains: map[int][][]*x509.Certificate{
		0: fakeChains("a", 2),
		1: fakeChains("b", 2),
		2: fakeChains("c", 2),
	}}
	req := newRequest(3, 2)

	rep, err := trust.PageChains(context.Background(), req, s.fetch)
	require.NoError(t, err)
	require.NotEmpty(t, rep.NextPageToken)
	// The page is full after subject 0, later subjects must not be fetched.
	assert.Equal(t, []int{0}, s.fetched)

	s.fetched = nil
	req.PageToken = rep.NextPageToken
	_, err = trust.PageChains(context.Background(), req, s.fetch)
	require.NoError(t, err)
	// Subject 0 was completely returned, it must not be fetched again.
	assert.Equal(t, []int{1}, s.fetched)
}

func TestPageChainsConcurrentInsert(t *testing.T) {
	s := &store{chains: map[int][][]*x509.Certificate{0: fakeChains("a", 6)}}
	original := map[string]bool{}
	for _, c := range s.chains[0] {
		original[string(c[0].Raw)+"|"+string(c[1].Raw)] = true
	}
	req := newRequest(1, 2)

	seen := map[string]int{}
	inserted := false
	for {
		rep, err := trust.PageChains(context.Background(), req, s.fetch)
		require.NoError(t, err)
		for _, c := range rep.Chains {
			seen[chainKey(c)]++
		}
		if rep.NextPageToken == "" {
			break
		}
		if !inserted {
			// Insert chains after the first page. Wherever they end up in the
			// order, existing chains must neither repeat nor be skipped.
			s.chains[0] = append(s.chains[0], fakeChains("new", 10)...)
			inserted = true
		}
		req.PageToken = rep.NextPageToken
	}
	for k := range original {
		assert.Equal(t, 1, seen[k], "chain %s", k)
	}
	for k, n := range seen {
		assert.Equal(t, 1, n, "chain %s returned more than once", k)
	}
}

func TestPageChainsInvalidInput(t *testing.T) {
	s := &store{chains: map[int][][]*x509.Certificate{
		0: fakeChains("a", 3),
		1: fakeChains("b", 3),
	}}
	first := func(t *testing.T) string {
		rep, err := trust.PageChains(context.Background(), newRequest(2, 2), s.fetch)
		require.NoError(t, err)
		require.NotEmpty(t, rep.NextPageToken)
		return rep.NextPageToken
	}

	t.Run("negative page size", func(t *testing.T) {
		_, err := trust.PageChains(context.Background(), newRequest(2, -1), s.fetch)
		assert.ErrorIs(t, err, pagination.ErrInvalidPageSize)
	})
	t.Run("garbage token", func(t *testing.T) {
		req := newRequest(2, 2)
		req.PageToken = "not a token!"
		_, err := trust.PageChains(context.Background(), req, s.fetch)
		assert.ErrorIs(t, err, pagination.ErrInvalidPageToken)
	})
	t.Run("truncated token", func(t *testing.T) {
		req := newRequest(2, 2)
		tok := first(t)
		req.PageToken = tok[:len(tok)-4]
		_, err := trust.PageChains(context.Background(), req, s.fetch)
		assert.ErrorIs(t, err, pagination.ErrInvalidPageToken)
	})
	t.Run("changed subjects", func(t *testing.T) {
		req := newRequest(2, 2)
		req.PageToken = first(t)
		req.Subjects[1].SubjectKeyId = []byte("other")
		_, err := trust.PageChains(context.Background(), req, s.fetch)
		assert.ErrorIs(t, err, pagination.ErrInvalidPageToken)
	})
	t.Run("changed validity", func(t *testing.T) {
		req := newRequest(2, 2)
		req.PageToken = first(t)
		req.AtLeastValidSince = 7
		_, err := trust.PageChains(context.Background(), req, s.fetch)
		assert.ErrorIs(t, err, pagination.ErrInvalidPageToken)
	})
	t.Run("changed page size is allowed", func(t *testing.T) {
		req := newRequest(2, 5)
		req.PageToken = first(t)
		_, err := trust.PageChains(context.Background(), req, s.fetch)
		assert.NoError(t, err)
	})
}
