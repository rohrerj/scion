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
	"hash/fnv"
)

type SaltHasher interface {
	Hash([]byte) uint32
}

type Fnv1aWithSalt struct {
	salt []byte
}

func NewFnv1aHasher(salt []byte) *Fnv1aWithSalt {
	return &Fnv1aWithSalt{
		salt: salt,
	}
}

func (h *Fnv1aWithSalt) Hash(b []byte) uint32 {
	hasher := fnv.New32a()
	hasher.Write(b)
	hasher.Write(h.salt)
	return hasher.Sum32()
}
