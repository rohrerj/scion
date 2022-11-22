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

package tokenbucket

import (
	"time"
)

type TokenBucket struct {
	CurrentTokens   float64
	LastTimeApplied time.Time

	//Burst Size
	CBS float64

	//In bytes per second
	CIR float64
}

func NewTokenBucket(initialTime time.Time, burstSize float64, rate float64) *TokenBucket {
	return &TokenBucket{
		CurrentTokens:   rate,
		CIR:             rate,
		CBS:             burstSize,
		LastTimeApplied: initialTime,
	}
}

func (t *TokenBucket) SetRate(rate float64) {
	t.CIR = rate
}

func (t *TokenBucket) SetBurstSize(burstSize float64) {
	t.CBS = burstSize
}

// Apply calculates the current available tokens and checks whether there are enough tokens available. The success is indicated by a bool.
func (t *TokenBucket) Apply(size int, now time.Time) bool {
	if !now.Before(t.LastTimeApplied) {
		t.CurrentTokens += now.Sub(t.LastTimeApplied).Seconds() * t.CIR
		t.CurrentTokens = min(t.CurrentTokens, t.CBS)
		t.LastTimeApplied = now
		if t.CurrentTokens >= float64(size) {
			t.CurrentTokens -= float64(size)
			return true
		} else {
			return false
		}
	}
	return false
}

// This function calculates the minimal value of two float64.
func min(a float64, b float64) float64 {
	if a > b {
		return b
	} else {
		return a
	}
}
