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

package monitor_test

import (
	"fmt"
	"testing"

	"github.com/scionproto/scion/pkg/experimental/pot/monitor"
)

func BenchmarkSamplers(b *testing.B) {
	sizes := []int{100, 500, 1000, 5000}
	out_sizes := []int{32, 64, 128, 256}
	samplers := []struct {
		name    string
		sampler monitor.Sampler
	}{
		{
			name:    "Stride Sampler",
			sampler: &monitor.StrideSampler{},
		},
		{
			name:    "FirstAndLast Sampler",
			sampler: &monitor.FirstAndLastSampler{},
		},
	}
	data := make([]byte, 5000)
	for i := 0; i < 5000; i++ {
		data[i] = byte(i)
	}
	for _, out_size := range out_sizes {
		out := make([]byte, out_size)
		for _, sampler := range samplers {
			for _, size := range sizes {
				b.Run(fmt.Sprintf("%s_payload_size_%d_out_size_%d", sampler.name, size, out_size), func(b *testing.B) {
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						sampler.sampler.Sample(data[:size], out)
					}
				})
			}
		}
	}
}
