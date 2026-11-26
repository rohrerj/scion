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

// Package pagination contains helpers shared by the paginated endhost API
// endpoints.
//
// A page token is opaque to the client. It consists of a format version, a
// hash of the request parameters that must not change between pages, and an
// endpoint specific cursor:
//
//	version (1 byte) | request hash (16 bytes) | cursor
//
// encoded with unpadded base64url.
package pagination

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash"

	"github.com/scionproto/scion/pkg/private/serrors"
)

const (
	tokenVersion = 1
	hashLen      = 16
)

var (
	// ErrInvalidPageSize indicates that the requested page size is invalid.
	ErrInvalidPageSize = serrors.New("invalid page size")
	// ErrInvalidPageToken indicates that the page token is malformed or does not
	// belong to the request it was sent with.
	ErrInvalidPageToken = serrors.New("invalid page token")
)

// PageSize returns the effective page size for the requested size. Zero and
// sizes larger than maxSize result in maxSize; negative sizes are rejected.
func PageSize(requested int32, maxSize int) (int, error) {
	switch {
	case requested < 0:
		return 0, serrors.JoinNoStack(ErrInvalidPageSize, nil, "page_size", requested)
	case requested == 0 || int(requested) > maxSize:
		return maxSize, nil
	default:
		return int(requested), nil
	}
}

// RequestHasher hashes the request parameters that must stay the same while
// paginating. Page size and page token must not be included.
type RequestHasher struct {
	h   hash.Hash
	buf [8]byte
}

func NewRequestHasher() *RequestHasher {
	return &RequestHasher{h: sha256.New()}
}

// Uint64 adds a fixed-size integer to the hash.
func (r *RequestHasher) Uint64(v uint64) {
	binary.BigEndian.PutUint64(r.buf[:], v)
	r.h.Write(r.buf[:])
}

// Bytes adds a length-prefixed byte slice to the hash.
func (r *RequestHasher) Bytes(b []byte) {
	r.Uint64(uint64(len(b)))
	r.h.Write(b)
}

// Sum returns the request hash.
func (r *RequestHasher) Sum() []byte {
	return r.h.Sum(nil)[:hashLen]
}

// EncodeToken encodes the cursor into a page token bound to the request hash.
// The cursor must not be empty.
func EncodeToken(reqHash, cursor []byte) string {
	b := make([]byte, 0, 1+hashLen+len(cursor))
	b = append(b, tokenVersion)
	b = append(b, reqHash...)
	b = append(b, cursor...)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeToken decodes a page token and verifies that it belongs to a request
// with the given request hash. It returns the cursor, which is nil for the
// empty token, i.e., the first page.
func DecodeToken(token string, reqHash []byte) ([]byte, error) {
	if token == "" {
		return nil, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, serrors.JoinNoStack(ErrInvalidPageToken, err)
	}
	if len(b) <= 1+hashLen || b[0] != tokenVersion {
		return nil, serrors.JoinNoStack(ErrInvalidPageToken, nil, "reason", "malformed header")
	}
	if !bytes.Equal(b[1:1+hashLen], reqHash) {
		return nil, serrors.JoinNoStack(ErrInvalidPageToken, nil,
			"reason", "request parameters differ from the request that issued the token")
	}
	return b[1+hashLen:], nil
}
