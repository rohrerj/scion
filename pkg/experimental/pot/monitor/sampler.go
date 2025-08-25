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

package monitor

type Sampler interface {
	Sample([]byte, []byte)
}

type StrideSampler struct{}

func (s *StrideSampler) Sample(data []byte, out []byte) {
	num_samples := len(out)
	dataLen := len(data)
	stride := dataLen / num_samples
	currentIndex := 0
	for i := 0; i < num_samples; i++ {
		out[i] = data[currentIndex]
		currentIndex += stride
	}
}
