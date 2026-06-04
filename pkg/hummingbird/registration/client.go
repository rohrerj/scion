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

package registration

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
	"github.com/scionproto/scion/private/trust"
)

type Client struct {
	accountClient hummingbirdconnect.AccountServiceClient
	name          string
}

func NewClient(c hummingbirdconnect.AccountServiceClient, name string) *Client {
	return &Client{
		accountClient: c,
		name:          name,
	}
}

func (c *Client) Register(ctx context.Context, signer trust.Signer) (string, string, error) {
	challengeResponse, err := c.accountClient.CreateChallenge(ctx, &connect.Request[hummingbird.CreateChallengeRequest]{
		Msg: &hummingbird.CreateChallengeRequest{
			Ia: uint64(signer.IA),
		},
	})
	if err != nil {
		return "", "", err
	}
	signedMsg, err := signer.Sign(ctx, challengeResponse.Msg.Challenge.Value, []byte(c.name))
	if err != nil {
		return "", "", err
	}
	registrationResponse, err := c.accountClient.RegisterAS(ctx, &connect.Request[hummingbird.RegisterASRequest]{
		Msg: &hummingbird.RegisterASRequest{
			Id:              challengeResponse.Msg.Challenge.Id,
			SignedChallenge: signedMsg,
		},
	})
	if err != nil {
		return "", "", err
	}
	fmt.Println("publisherToken", registrationResponse.Msg.JwtPublisher)
	fmt.Println("redemptionToken", registrationResponse.Msg.JwtRedemption)
	return registrationResponse.Msg.JwtPublisher, registrationResponse.Msg.JwtRedemption, nil
}
