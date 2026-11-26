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

package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"sort"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/private/pagination"
	truststorage "github.com/scionproto/scion/private/storage/trust"
)

// MaxChainsPageSize is the maximum (and default) number of chains returned per page.
const MaxChainsPageSize = 64

// ChainFetcher returns the chains for the subject at index subjectIdx of the request.
type ChainFetcher func(ctx context.Context, subjectIdx int) ([][]*x509.Certificate, error)

// chainCursor identifies the position after the last chain that was returned.
type chainCursor struct {
	// subjectIdx is the index of the subject in the request to continue with.
	subjectIdx int
	// lastChainID is the ID of the last chain returned for subjectIdx. If nil,
	// the subject is processed from the beginning.
	lastChainID []byte
}

// PageChains returns one page of chains for the given request.
//
// Subjects are processed in request order, and the chains of each subject are
// ordered by their chain ID. The page token is a cursor holding the subject
// index and the ID of the last chain returned. Subjects before the cursor are
// not fetched again, and subjects after a full page are not fetched at all.
//
// Chains that are added while a client is paginating may or may not be
// included. Chains that existed when the first page was requested are returned
// exactly once.
//
// If the page fills up exactly at a subject boundary, a page token is returned
// even if the remaining subjects turn out to have no chains, so the last page
// can be empty.
//
// Invalid page sizes and page tokens result in errors wrapping
// pagination.ErrInvalidPageSize and pagination.ErrInvalidPageToken.
func PageChains(
	ctx context.Context,
	req *endhost.ListChainsRequest,
	fetch ChainFetcher,
) (*endhost.ListChainsResponse, error) {

	pageSize, err := pagination.PageSize(req.PageSize, MaxChainsPageSize)
	if err != nil {
		return nil, err
	}
	reqHash := chainsRequestHash(req)
	var cur chainCursor
	if raw, err := pagination.DecodeToken(req.PageToken, reqHash); err != nil {
		return nil, err
	} else if raw != nil {
		if cur, err = decodeChainCursor(raw); err != nil {
			return nil, err
		}
		if cur.subjectIdx >= len(req.Subjects) {
			return nil, serrors.JoinNoStack(pagination.ErrInvalidPageToken, nil,
				"reason", "subject index out of range")
		}
	}

	rep := &endhost.ListChainsResponse{
		Chains: make([]*endhost.Chain, 0, pageSize),
	}
	for i := cur.subjectIdx; i < len(req.Subjects); i++ {
		if len(rep.Chains) == pageSize {
			rep.NextPageToken = pagination.EncodeToken(reqHash,
				encodeChainCursor(chainCursor{subjectIdx: i}))
			return rep, nil
		}
		chains, err := fetch(ctx, i)
		if err != nil {
			return nil, err
		}
		chains, ids := sortChains(chains)

		start := 0
		if i == cur.subjectIdx && cur.lastChainID != nil {
			start = sort.Search(len(ids), func(k int) bool {
				return bytes.Compare(ids[k], cur.lastChainID) > 0
			})
		}
		subject := req.Subjects[i]
		for j := start; j < len(chains); j++ {
			if len(rep.Chains) == pageSize {
				// j > start holds, because the page was not full at the start
				// of this subject.
				rep.NextPageToken = pagination.EncodeToken(reqHash,
					encodeChainCursor(chainCursor{subjectIdx: i, lastChainID: ids[j-1]}))
				return rep, nil
			}
			rep.Chains = append(rep.Chains, &endhost.Chain{
				Subject: subject,
				AsCert:  chains[j][0].Raw,
				CaCert:  chains[j][1].Raw,
			})
		}
	}
	return rep, nil
}

// sortChains sorts the chains by their chain ID and removes duplicates. It
// returns the sorted chains and their IDs.
func sortChains(chains [][]*x509.Certificate) ([][]*x509.Certificate, [][]byte) {
	type entry struct {
		chain []*x509.Certificate
		id    []byte
	}
	entries := make([]entry, 0, len(chains))
	for _, c := range chains {
		entries = append(entries, entry{chain: c, id: truststorage.ChainID(c)})
	}
	sort.Slice(entries, func(a, b int) bool {
		return bytes.Compare(entries[a].id, entries[b].id) < 0
	})
	sorted := make([][]*x509.Certificate, 0, len(entries))
	ids := make([][]byte, 0, len(entries))
	for k, e := range entries {
		if k > 0 && bytes.Equal(e.id, entries[k-1].id) {
			continue
		}
		sorted = append(sorted, e.chain)
		ids = append(ids, e.id)
	}
	return sorted, ids
}

// chainsRequestHash hashes all request parameters except for the page size and
// the page token.
func chainsRequestHash(req *endhost.ListChainsRequest) []byte {
	h := pagination.NewRequestHasher()
	h.Uint64(uint64(req.AtLeastValidSince))
	h.Uint64(uint64(req.AtLeastValidUntil))
	h.Uint64(uint64(len(req.Subjects)))
	for _, s := range req.Subjects {
		h.Uint64(s.IsdAs)
		h.Bytes(s.SubjectKeyId)
	}
	return h.Sum()
}

// encodeChainCursor encodes the cursor as: subject index (uvarint) | last chain ID.
func encodeChainCursor(c chainCursor) []byte {
	b := binary.AppendUvarint(nil, uint64(c.subjectIdx))
	return append(b, c.lastChainID...)
}

func decodeChainCursor(b []byte) (chainCursor, error) {
	idx, n := binary.Uvarint(b)
	if n <= 0 || idx > uint64(^uint32(0)) {
		return chainCursor{}, serrors.JoinNoStack(pagination.ErrInvalidPageToken, nil,
			"reason", "malformed subject index")
	}
	var lastID []byte
	switch rest := b[n:]; len(rest) {
	case 0:
	case sha256.Size:
		lastID = rest
	default:
		return chainCursor{}, serrors.JoinNoStack(pagination.ErrInvalidPageToken, nil,
			"reason", "malformed chain ID")
	}
	return chainCursor{subjectIdx: int(idx), lastChainID: lastID}, nil
}
