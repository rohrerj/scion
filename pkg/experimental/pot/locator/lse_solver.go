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
	n := len(m)
	if n == 0 || len(b) == 0 {
		return nil
	}
	k := len(m[0])

	// Augment matrix with b
	aug := make([][]uint8, n)
	for i := 0; i < n; i++ {
		row := make([]uint8, k+1)
		copy(row, m[i])
		row[k] = b[i]
		aug[i] = row
	}

	// Gaussian elimination (forward)
	row := 0
	for col := 0; col < k && row < n; col++ {
		// Find pivot
		pivot := row
		for pivot < n && aug[pivot][col] == 0 {
			pivot++
		}
		if pivot == n {
			continue // no pivot in this column
		}

		// Swap pivot into place
		aug[row], aug[pivot] = aug[pivot], aug[row]

		// Eliminate below
		for r := row + 1; r < n; r++ {
			if aug[r][col] == 1 {
				for c := col; c <= k; c++ {
					aug[r][c] ^= aug[row][c]
				}
			}
		}

		row++
	}

	// Check for inconsistency: 0 = 1
	for i := 0; i < n; i++ {
		allZero := true
		for j := 0; j < k; j++ {
			if aug[i][j] != 0 {
				allZero = false
				break
			}
		}
		if allZero && aug[i][k] == 1 {
			return nil // no solution
		}
	}

	// Back substitution
	x := make([]uint8, k)

	for i := n - 1; i >= 0; i-- {
		pivotCol := -1
		for c := 0; c < k; c++ {
			if aug[i][c] == 1 {
				pivotCol = c
				break
			}
		}
		if pivotCol == -1 {
			continue
		}

		sum := aug[i][k]
		for c := pivotCol + 1; c < k; c++ {
			sum ^= aug[i][c] & x[c]
		}
		x[pivotCol] = sum
	}

	return x
}
