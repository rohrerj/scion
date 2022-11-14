// Copyright 2022 ETH Zurich
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

package coligate

import (
	"hash"
	"hash/fnv"
)

type SaltHasher interface {
	Init(string)
	Hash(string) uint32
}

type Fnv1aWithSalt struct {
	salt string
	hash hash.Hash32
}

func (h *Fnv1aWithSalt) Init(salt string) {
	h.hash = fnv.New32a()
	h.salt = salt
}

func (h *Fnv1aWithSalt) Hash(s string) uint32 {
	h.hash.Reset()
	h.hash.Write([]byte(s + h.salt))
	return h.hash.Sum32()
}

func (h *Fnv1aWithSalt) Hash2(s string) uint32 {
	hh := fnv.New32a()
	hh.Write([]byte(s + h.salt))
	return hh.Sum32()
}

// Creates and returns an newly initialized Fnv1a hasher
func CreateFnv1aHasher(salt string) *Fnv1aWithSalt {
	h := &Fnv1aWithSalt{}
	h.Init(salt)
	return h
}

type AnotherHasher struct {
	salt []byte
}

func NewAnotherHasher(salt []byte) *AnotherHasher {
	return &AnotherHasher{
		salt: salt,
	}
}

func (h *AnotherHasher) Hash(b []byte) uint32 {
	hasher := fnv.New32a()
	hasher.Write(b)
	hasher.Write(h.salt)
	return hasher.Sum32()
}
