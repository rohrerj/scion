// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncodingsRoundTrip checks that EncodeInts data is readable by EncodingsToInts.
func TestEncodingsRoundTrip(t *testing.T) {
	testCases := map[string][]uint32{
		"empty":    {},
		"one":      {42},
		"a few":    {1, 2, 3, 4, 5},
		"extremes": {0, 1, 1 << 31, ^uint32(0)},
	}
	for name, points := range testCases {
		t.Run(name, func(t *testing.T) {
			r := &RedemptionDelegation{}
			r.EncodeInts(points)
			got, err := r.EncodingsToInts()
			require.NoError(t, err)
			assert.Equal(t, points, got)
		})
	}
}

// TestEncodingsToIntsRejectsACorruptBlob checks that the encodings whose length is not a
// multiple of 4 is reported. Currently, this situation can only come from a corrupt DB row.
func TestEncodingsToIntsRejectsACorruptBlob(t *testing.T) {
	for _, length := range []int{1, 2, 3, 5, 7} {
		r := &RedemptionDelegation{Encodings: make([]byte, length)}
		assert.NotPanics(t, func() {
			got, err := r.EncodingsToInts()
			require.Error(t, err, "a blob of %d bytes must be refused", length)
			assert.Nil(t, got)
			assert.Contains(t, err.Error(), "encoding points")
		})
	}
}

// TestEncodingsToIntsOnAnEmptyBlob checks the boundary: "empty" encodings are not corrupt.
func TestEncodingsToIntsOnAnEmptyBlob(t *testing.T) {
	r := &RedemptionDelegation{}
	got, err := r.EncodingsToInts()
	require.NoError(t, err)
	assert.Empty(t, got)
}
