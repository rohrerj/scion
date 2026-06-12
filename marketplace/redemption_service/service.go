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

package redemption

import (
	"time"

	"github.com/scionproto/scion/pkg/proto/hummingbird"
)

type RedemptionService struct {
	SendChannel   chan *hummingbird.RedeemAssetFromASRequest
	Pending       map[uint64]chan *hummingbird.RedeemAssetFromASResponse
	UpdateChannel chan *RedemptionDelegationUpdate
}

type RedemptionDelegationUpdate struct {
	ExpirationTime time.Time
}

func NewRedemptionService(sendCh chan *hummingbird.RedeemAssetFromASRequest,
	pending map[uint64]chan *hummingbird.RedeemAssetFromASResponse) *RedemptionService {
	s := &RedemptionService{
		SendChannel:   sendCh,
		Pending:       pending,
		UpdateChannel: make(chan *RedemptionDelegationUpdate, 1),
	}
	go s.readRoutine()
	return s
}

func (s *RedemptionService) readRoutine() {
	var err error
	for {
		select {
		case u := <-s.UpdateChannel:
			if err = s.handleUpdate(u); err != nil {
				return
			}
		case r := <-s.SendChannel:
			s.handleRequest(r)
		}
	}
}

func (s *RedemptionService) handleUpdate(u *RedemptionDelegationUpdate) error {
	return nil
}

func (s *RedemptionService) handleRequest(r *hummingbird.RedeemAssetFromASRequest) {

}
