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

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/marketplace/db"
	"github.com/scionproto/scion/marketplace/storage"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird/registration"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
)

type ASAccountManager struct {
	store               *storage.MarketplaceStorage
	registrationService *registration.Service
}

func ASAccountManagerInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			authority := req.Header().Get(":authority")
			if authority == "" {
				authority = req.Header().Get("host")
			}

			ctx = context.WithValue(ctx, "authority", authority)
			return next(ctx, req)
		}
	}
}

func (s *ASAccountManager) CreateChallenge(ctx context.Context, req *connect.Request[hummingbird.CreateChallengeRequest]) (*connect.Response[hummingbird.CreateChallengeResponse], error) {
	id, challenge, err := s.registrationService.CreateChallenge(ctx, addr.IA(req.Msg.Ia))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return &connect.Response[hummingbird.CreateChallengeResponse]{
		Msg: &hummingbird.CreateChallengeResponse{
			Challenge: &hummingbird.ASChallenge{
				Id:    id,
				Value: challenge,
			},
		},
	}, nil
}

func (s *ASAccountManager) RegisterAS(ctx context.Context, req *connect.Request[hummingbird.RegisterASRequest]) (*connect.Response[hummingbird.RegisterASResponse], error) {
	authority := ctx.Value("authority").(string)
	publisherToken, redemptionToken, ia, err := s.registrationService.RegisterAS(ctx, req.Msg.Id, req.Msg.SignedChallenge, authority)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	_, err = s.store.CreateASUser(ctx, &db.DBASUser{
		IA: uint64(ia),
	})
	if err != nil {
		fmt.Println(err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return &connect.Response[hummingbird.RegisterASResponse]{
		Msg: &hummingbird.RegisterASResponse{
			JwtPublisher:  publisherToken,
			JwtRedemption: redemptionToken,
		},
	}, nil
}

func NewASAccountManager(store *storage.MarketplaceStorage, regService *registration.Service) *ASAccountManager {
	return &ASAccountManager{
		store:               store,
		registrationService: regService,
	}
}

func (s *ASAccountManager) ResetJWT(ctx context.Context, req *connect.Request[hummingbird.JWTResetRequest]) (*connect.Response[hummingbird.JWTResetResponse], error) {
	/*name, err := subjectFromCtx(ctx)
	if err != nil {
		return nil, err
	}
	user := s.db.GetASUser(name)
	if user != nil {
		user.TokenVersion++
	}*/
	return &connect.Response[hummingbird.JWTResetResponse]{Msg: &hummingbird.JWTResetResponse{}}, nil
}
