// Copyright 2024 ETH Zurich
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

package path

import (
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
)

func (e Empty) SetExtensions(s *slayers.SCION, p *snet.PacketInfo) error {
	return nil
}

func (e *EPIC) SetExtensions(s *slayers.SCION, p *snet.PacketInfo) error {
	return nil
}

func (p OneHop) SetExtensions(s *slayers.SCION, pi *snet.PacketInfo) error {
	return nil
}

func (p SCION) SetExtensions(s *slayers.SCION, pi *snet.PacketInfo) error {
	return nil
}