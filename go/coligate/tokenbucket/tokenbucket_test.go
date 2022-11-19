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

package Tokenbucket_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	Tokenbucket "github.com/scionproto/scion/go/coligate/tokenbucket"
)

type entry struct {
	entry  Tokenbucket.Entry
	result bool
}
type test struct {
	name    string
	entries []entry
	bucket  Tokenbucket.TokenBucket
}

// Tests the Token Bucket Algorithm by running subtests.
func TestGroupForTokenBucketAlgorithm(t *testing.T) {

	var startTime = time.Unix(0, 0)

	tests := []test{
		{
			name: "TestNoDropsWhenSendingWithinLimit",
			bucket: Tokenbucket.TokenBucket{
				CIRInBytes:        1024,
				CurrentTokens:     1024,
				LastPacketTime:    startTime,
				TokenIntervalInMs: 1,
			},
			entries: []entry{
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(0 * 256 * time.Millisecond)),
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(1 * 256 * time.Millisecond)),
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(2 * 256 * time.Millisecond)),
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(3 * 256 * time.Millisecond)),
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(4 * 256 * time.Millisecond)),
					},
					result: true,
				},
			}},
		{
			name: "TestPacketOutsideLimitIsDropped",
			bucket: Tokenbucket.TokenBucket{
				CIRInBytes:        1024,
				CurrentTokens:     1024,
				LastPacketTime:    startTime,
				TokenIntervalInMs: 1,
			},
			entries: []entry{
				{
					entry: Tokenbucket.Entry{
						Length:      1000,
						ArrivalTime: startTime,
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime,
					},
					result: false,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      24,
						ArrivalTime: startTime,
					},
					result: true,
				},
			}},
		{
			name: "TestOneLargePacketWithinLimitIsNotDropped",
			bucket: Tokenbucket.TokenBucket{
				CIRInBytes:        1024,
				CurrentTokens:     1024,
				LastPacketTime:    startTime,
				TokenIntervalInMs: 1,
			},
			entries: []entry{
				{
					entry: Tokenbucket.Entry{
						Length:      1024,
						ArrivalTime: startTime,
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      1,
						ArrivalTime: startTime,
					},
					result: false,
				},
			}},
		{
			name: "TestPacketLargerThanCIRIsDropped",
			bucket: Tokenbucket.TokenBucket{
				CIRInBytes:        1024,
				CurrentTokens:     1024,
				LastPacketTime:    startTime,
				TokenIntervalInMs: 1,
			},
			entries: []entry{
				{
					entry: Tokenbucket.Entry{
						Length:      2048,
						ArrivalTime: startTime,
					},
					result: false,
				},
			}},
		{
			name: "TestBurst",
			bucket: Tokenbucket.TokenBucket{
				CIRInBytes:        1024,
				CurrentTokens:     0,
				LastPacketTime:    startTime,
				TokenIntervalInMs: 10,
			},
			entries: []entry{
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(249 * time.Millisecond)),
					},
					result: false,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(250 * time.Millisecond)),
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(499 * time.Millisecond)),
					},
					result: false,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(500 * time.Millisecond)),
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(749 * time.Millisecond)),
					},
					result: false,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(750 * time.Millisecond)),
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(999 * time.Millisecond)),
					},
					result: false,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime.Add(time.Duration(1000 * time.Millisecond)),
					},
					result: true,
				},
			}},
		{
			name: "TestMultiplePacketsAtSameTimeWithinLimitDoNotGetDropped",
			bucket: Tokenbucket.TokenBucket{
				CIRInBytes:        1024,
				CurrentTokens:     1024,
				LastPacketTime:    startTime,
				TokenIntervalInMs: 10,
			},
			entries: []entry{
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime,
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime,
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime,
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      256,
						ArrivalTime: startTime,
					}, result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      1,
						ArrivalTime: startTime,
					},
					result: false,
				},
			}},
		{
			name: "TestExhaustedLimitGetsRefilledOverTime",
			bucket: Tokenbucket.TokenBucket{
				CIRInBytes:        1024,
				CurrentTokens:     1024,
				LastPacketTime:    startTime,
				TokenIntervalInMs: 10,
			},
			entries: []entry{
				{
					entry: Tokenbucket.Entry{
						Length:      1024,
						ArrivalTime: startTime,
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      1024,
						ArrivalTime: startTime.Add(time.Duration(999 * time.Millisecond)),
					},
					result: false,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      1024,
						ArrivalTime: startTime.Add(time.Duration(1000 * time.Millisecond)),
					},
					result: true,
				},
			}},
		{
			name: "TestTokenBucketDoesNotOverfillWithLargeTimeDifferences",
			bucket: Tokenbucket.TokenBucket{
				CIRInBytes:        1024,
				CurrentTokens:     1024,
				LastPacketTime:    startTime,
				TokenIntervalInMs: 10,
			},
			entries: []entry{
				{
					entry: Tokenbucket.Entry{
						Length:      1024,
						ArrivalTime: startTime,
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      1025,
						ArrivalTime: startTime.Add(time.Duration(24 * time.Hour)),
					},
					result: false,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      1024,
						ArrivalTime: startTime.Add(time.Duration(24 * time.Hour)),
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      1,
						ArrivalTime: startTime.Add(time.Duration(24 * time.Hour)),
					},
					result: false,
				},
			}},
		{
			name: "TestTokenBucketWorksWithLargeCIRValues",
			bucket: Tokenbucket.TokenBucket{
				CIRInBytes:        107374182400,
				CurrentTokens:     0,
				LastPacketTime:    startTime,
				TokenIntervalInMs: 10,
			},
			entries: []entry{
				{
					entry: Tokenbucket.Entry{
						Length:      107374182400,
						ArrivalTime: startTime.Add(time.Duration(999 * time.Millisecond)),
					},
					result: false,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      107374182400,
						ArrivalTime: startTime.Add(time.Duration(1000 * time.Millisecond)),
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      1073741824,
						ArrivalTime: startTime.Add(time.Duration(1009 * time.Millisecond)),
					},
					result: false,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      1073741824,
						ArrivalTime: startTime.Add(time.Duration(1010 * time.Millisecond)),
					},
					result: true,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      107374182401,
						ArrivalTime: startTime.Add(time.Duration(24 * time.Hour)),
					},
					result: false,
				},
				{
					entry: Tokenbucket.Entry{
						Length:      107374182400,
						ArrivalTime: startTime.Add(time.Duration(24 * time.Hour)),
					},
					result: true,
				},
			}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, en := range tc.entries {
				assert.Equal(t, en.result, tc.bucket.ValidateBandwidth(&en.entry), tc.name)
			}
		})
	}
}
