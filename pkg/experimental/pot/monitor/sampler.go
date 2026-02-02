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

// StrideSampler samples using a computed stride depending on the data and out length.
// Requires that len(data) >= len(out).
type StrideSampler struct{}

func (s *StrideSampler) Sample(data []byte, out []byte) {
	if len(data) < len(out) {
		copy(out, data)
		return
	}
	num_samples := len(out)
	dataLen := len(data)
	stride := dataLen / num_samples
	currentIndex := 0
	for i := 0; i < num_samples; i++ {
		out[i] = data[currentIndex]
		currentIndex += stride
	}
}

// FirstAndLastSampler samples the N/2 first and N/2 last bytes of data.
// Requires that len(data) >= len(out) and len(out) is divisible by 2.
type FirstAndLastSampler struct{}

func (s *FirstAndLastSampler) Sample(data []byte, out []byte) {
	if len(data) < len(out) {
		copy(out, data)
		return
	}
	halfSampleLen := len(out) >> 2
	dataLen := len(data)
	copy(out[:halfSampleLen], data[:halfSampleLen])
	copy(out[halfSampleLen:], data[dataLen-halfSampleLen:])
}
