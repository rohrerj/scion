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
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt"
	"github.com/scionproto/scion/marketplace/db"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird/registration"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
)

func ASAccountManagerInterceptor(verifier *TokenVerifier) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			authority := req.Header().Get(":authority")
			if authority == "" {
				authority = req.Header().Get("host")
			}

			ctx = context.WithValue(ctx, "authority", authority)
			authHeader := req.Header().Get("Authorization")

			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
				if tokenStr != "" {
					var err error
					ctx, err = verifier.contextFromJwt(ctx, tokenStr, "")
					if err != nil {
						return nil, err
					}
				}
			}
			return next(ctx, req)
		}
	}
}

func (s *Service) CreateChallenge(ctx context.Context, req *connect.Request[hummingbird.CreateChallengeRequest]) (*connect.Response[hummingbird.CreateChallengeResponse], error) {
	challenge, err := s.registrationService.CreateChallenge(ctx, addr.IA(req.Msg.Ia))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return &connect.Response[hummingbird.CreateChallengeResponse]{
		Msg: challenge,
	}, nil
}

func (s *Service) RegisterAS(ctx context.Context, req *connect.Request[hummingbird.RegisterASRequest]) (*connect.Response[hummingbird.RegisterASResponse], error) {
	authority, ok := ctx.Value("authority").(string)
	if !ok || authority == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, serrors.New("Request must provide HTTP Host or HTTP2 :authority header"))
	}
	fmt.Println("Register AS", "Authority", authority)
	ia, err := s.registrationService.RegisterAS(ctx, req.Msg.Id, req.Msg.SignedChallenge, authority)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	dbUser, err := s.store.GetASUser(ctx, ia)
	if err != nil {
		fmt.Println(err)

		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if dbUser == nil {
		dbUser = &db.DBASUser{
			IA:           ia,
			TokenVersion: 0,
		}
		_, err = s.store.CreateASUser(ctx, dbUser)
		if err != nil {
			fmt.Println(err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	now := time.Now()
	publisherToken, err := s.signer.GenerateToken(jwt.MapClaims{
		"sub":   ia.String(),
		"scope": registration.ScopeAssetPublisher,
		"exp":   now.Add(time.Hour * 24 * 7).Unix(),
		"iat":   now.Unix(),
		"ver":   dbUser.TokenVersion,
	})
	if err != nil {
		fmt.Println(err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	redemptionToken, err := s.signer.GenerateToken(jwt.MapClaims{
		"sub":   ia.String(),
		"scope": registration.ScopeRedemptionService,
		"exp":   now.Add(time.Hour * 24 * 7).Unix(),
		"iat":   now.Unix(),
		"ver":   dbUser.TokenVersion,
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

func (s *Service) ResetJWT(ctx context.Context, req *connect.Request[hummingbird.JWTResetRequest]) (*connect.Response[hummingbird.JWTResetResponse], error) {
	ver, ok := ctx.Value("ver").(int64)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, serrors.New("invalid token"))
	}
	v := ctx.Value("user")
	switch x := v.(type) {
	case nil:
		return nil, connect.NewError(connect.CodeUnauthenticated, serrors.New("invalid token"))
	case int64:
		_, err := s.store.IncrementUserJWTVersion(ctx, x, ver)
		if err != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		}
	case addr.IA:
		_, err := s.store.IncrementASJWTVersion(ctx, x, ver)
		if err != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		}
		kickRedemptionService := func() {
			s.mtx.Lock()
			defer s.mtx.Unlock()
			peer, found := s.redemptionServerPeers[x]
			if !found {
				return
			}
			peer.mtx.Lock()
			defer peer.mtx.Unlock()
			if peer.cancelOldConnection != nil {
				peer.cancelOldConnection()
			}
		}
		kickRedemptionService()
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, serrors.New("invalid token"))
	}
	return &connect.Response[hummingbird.JWTResetResponse]{Msg: &hummingbird.JWTResetResponse{}}, nil
}
