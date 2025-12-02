// Copyright 2025 ETH Zurich
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

package locator_test

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/scionproto/scion/pkg/experimental/pot/locator"
)

func TestSolveGF2_Simple(t *testing.T) {
	m := [][]uint8{
		{1, 1},
		{0, 1},
	}
	b := []uint8{1, 0}

	x := locator.SolveGF2LSE(m, b)

	want := []uint8{1, 0}
	if !reflect.DeepEqual(x, want) {
		t.Fatalf("solution mismatch: got %v, want %v", x, want)
	}
}

func TestSolveGF2_Underdetermined(t *testing.T) {
	m := [][]uint8{
		{1, 1},
	}
	b := []uint8{1}

	x := locator.SolveGF2LSE(m, b)

	// Check equation m*x = b mod 2
	got := (m[0][0]*x[0] + m[0][1]*x[1]) % 2
	if got != b[0] {
		t.Fatalf("returned solution does not satisfy equation: got %d, want %d", got, b[0])
	}
}

func apply(M [][]uint8, x []uint8) []uint8 {
	n := len(M)
	res := make([]uint8, n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			res[i] ^= (M[i][j] & x[j])
		}
	}
	return res
}

func randomLSE(n int) (M [][]uint8, x []uint8, b []uint8) {
	M = make([][]uint8, n)
	for i := 0; i < n; i++ {
		M[i] = make([]uint8, n)
		for j := 0; j < n; j++ {
			M[i][j] = uint8(rand.Intn(2))
		}
	}
	x = make([]uint8, n)
	for i := range x {
		x[i] = uint8(rand.Intn(2))
	}
	b = apply(M, x)
	return
}

func equalVec(a, b []uint8) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func FuzzSolveGF2(f *testing.F) {
	f.Add(20) // initial seed: dimension 20

	f.Fuzz(func(t *testing.T, n int) {
		if n < 1 || n > 100 {
			t.Skip()
		}

		M, _, b := randomLSE(n)

		x := locator.SolveGF2LSE(M, b)

		got := apply(M, x)
		//expect := apply(M, xTrue)

		if !equalVec(got, b) {
			t.Fatalf("Mx != b")
		}

		// Note: solution may differ from xTrue (many solutions exist)
	})
}
