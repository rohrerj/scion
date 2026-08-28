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

package marketplace

import "github.com/scionproto/scion/pkg/proto/hummingbird"

func (s *RedemptionService) SetEncodingPoints(encodings []uint32) {
	s.encodingPoints = encodings
}

func (s *RedemptionService) EncodeBandwidth(bw uint32) uint16 {
	return (s.encodeBandwidth(bw))
}

// Out exposes the queue of a connection, so that a test can observe the requests
// the handler routes to it.
func (c *RemoteConn) Out() <-chan *hummingbird.RedeemAssetFromASRequest {
	return c.out
}
