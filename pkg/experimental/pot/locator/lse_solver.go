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

package locator

func SolveGF2LSE(m [][]uint8, b []uint8) []uint8 {
	n := len(m) // number of rows
	if n == 0 {
		return nil
	}
	k := len(m[0]) // number of columns

	// Augment matrix with b
	aug := make([][]uint8, n)
	for i := range m {
		row := make([]uint8, k+1)
		copy(row, m[i])
		row[k] = b[i]
		aug[i] = row
	}

	// Gaussian elimination (forward)
	col := 0
	for row := 0; row < n && col < k; col++ {
		// Find pivot
		pivot := row
		for pivot < n && aug[pivot][col] == 0 {
			pivot++
		}
		if pivot == n {
			continue // no pivot in this column
		}

		// Swap pivot to current row
		aug[row], aug[pivot] = aug[pivot], aug[row]

		// Eliminate downward
		for r := row + 1; r < n; r++ {
			if aug[r][col] == 1 {
				for c := col; c <= k; c++ {
					aug[r][c] ^= aug[row][c]
				}
			}
		}

		row++
	}

	// Back substitution
	x := make([]uint8, k)
	for row := n - 1; row >= 0; row-- {
		// Find first 1 (pivot column)
		pivotCol := -1
		for c := 0; c < k; c++ {
			if aug[row][c] == 1 {
				pivotCol = c
				break
			}
		}
		if pivotCol == -1 {
			continue // row is all zeros, skip
		}

		// Compute value for this pivot variable
		sum := aug[row][k]
		for c := pivotCol + 1; c < k; c++ {
			sum ^= (aug[row][c] & x[c])
		}
		x[pivotCol] = sum
	}

	return x
}
