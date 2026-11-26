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
	"bytes"
	"encoding/binary"
	"sort"
	"time"

	cache "zgo.at/zcache/v2"

	"github.com/scionproto/scion/pkg/addr"
	seg "github.com/scionproto/scion/pkg/segment"
)

type Key struct {
	Src addr.IA
	Dst addr.IA
}

type Store struct {
	c *cache.Cache[Key, SortedPaths]
}

type CombinedPath struct {
	UpSegment   *seg.PathSegment
	CoreSegment *seg.PathSegment
	DownSegment *seg.PathSegment
}

func (c *CombinedPath) Length() int {
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

// SortedPaths is a list of combined paths in pagination order, i.e., sorted by
// length and then by the IDs of their segments, without duplicates. Create it
// with SortPaths.
type SortedPaths struct {
	paths []CombinedPath
	// keys[i] is the sort key of paths[i]. Keys are unique and ascending.
	keys [][]byte
}

// SortPaths sorts the paths by length, breaking ties by the IDs of their
// segments, and removes paths that consist of segments with the same IDs.
// The order does not depend on the order of the input, so it stays the same
// when the paths are recomputed.
func SortPaths(paths []CombinedPath) SortedPaths {
	type entry struct {
		path CombinedPath
		key  []byte
	}
	entries := make([]entry, 0, len(paths))
	for _, p := range paths {
		entries = append(entries, entry{path: p, key: pathKey(p)})
	}
	sort.Slice(entries, func(a, b int) bool {
		return bytes.Compare(entries[a].key, entries[b].key) < 0
	})
	sorted := SortedPaths{
		paths: make([]CombinedPath, 0, len(entries)),
		keys:  make([][]byte, 0, len(entries)),
	}
	for i, e := range entries {
		if i > 0 && bytes.Equal(e.key, entries[i-1].key) {
			continue
		}
		sorted.paths = append(sorted.paths, e.path)
		sorted.keys = append(sorted.keys, e.key)
	}
	return sorted
}

// Len returns the number of paths.
func (s SortedPaths) Len() int {
	return len(s.paths)
}

// Paths returns the sorted paths. The returned slice must not be modified.
func (s SortedPaths) Paths() []CombinedPath {
	return s.paths
}

// search returns the index of the first path whose key is >= key.
func (s SortedPaths) search(key []byte) int {
	return sort.Search(len(s.keys), func(i int) bool {
		return bytes.Compare(s.keys[i], key) >= 0
	})
}

// pathKey returns the sort key of a path:
// length (4 bytes, big-endian) | up | core | down,
// where each segment is encoded as 0x00 if absent, or 0x01 | segment ID.
// Comparing keys bytewise orders paths by length first.
func pathKey(p CombinedPath) []byte {
	key := binary.BigEndian.AppendUint32(nil, uint32(p.Length()))
	for _, s := range []*seg.PathSegment{p.UpSegment, p.CoreSegment, p.DownSegment} {
		if s == nil {
			key = append(key, 0)
			continue
		}
		key = append(key, 1)
		key = append(key, s.ID()...)
	}
	return key
}

func NewStore() *Store {
	return &Store{
		c: cache.New[Key, SortedPaths](time.Minute, time.Minute),
	}
}

func (s *Store) Set(src addr.IA, dst addr.IA, paths SortedPaths) {
	s.c.Set(Key{Src: src, Dst: dst}, paths)
}

func (s *Store) Get(src addr.IA, dst addr.IA) (SortedPaths, bool) {
	return s.c.Get(Key{Src: src, Dst: dst})
}
