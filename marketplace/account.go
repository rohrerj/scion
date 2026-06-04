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
	"sync"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird/registration"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type User struct {
	Username     string
	Password     string
	TokenVersion uint64
	Reservations *[]*Reservation
	mtx          sync.RWMutex
	Balance      uint64
}

func (u *User) AddBalance(b uint64) {
	u.mtx.Lock()
	defer u.mtx.Unlock()
	if u.Balance+b > u.Balance {
		u.Balance += b
	}
}

type ASUser struct {
	IA           addr.IA
	TokenVersion uint64
}

type AccountDB struct {
	users map[string]*User
	ases  map[addr.IA]*ASUser
	mtx   sync.RWMutex
}

func NewAccountDB() *AccountDB {
	return &AccountDB{
		users: make(map[string]*User),
		ases:  make(map[addr.IA]*ASUser),
	}
}
func (db *AccountDB) GetUser(name string) *User {
	db.mtx.RLock()
	defer db.mtx.RUnlock()
	return db.users[name]
}
func (db *AccountDB) GetASUser(ia addr.IA) *ASUser {
	db.mtx.RLock()
	defer db.mtx.RUnlock()
	return db.ases[ia]
}
func (db *AccountDB) CreateNonExistingUser(user *User) bool {
	if user == nil {
		return false
	}
	db.mtx.RLock()
	if db.users[user.Username] == nil {
		db.mtx.RUnlock()
		db.mtx.Lock()
		defer db.mtx.Unlock()
		if db.users[user.Username] == nil {
			db.users[user.Username] = user
			if user.Reservations == nil {
				user.Reservations = &[]*Reservation{}
			}
			return true
		}
	} else {
		db.mtx.RUnlock()
	}

	return false
}
func (db *AccountDB) CreateNonExistingASUser(user *ASUser) bool {
	if user == nil {
		return false
	}
	db.mtx.Lock()
	defer db.mtx.Unlock()
	if db.ases[user.IA] == nil {
		db.ases[user.IA] = user
		return true
	}
	return false
}

func subjectFromCtx(ctx context.Context) (addr.IA, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return 0, connect.NewError(
			connect.CodeUnauthenticated,
			fmt.Errorf("missing peer info"),
		)
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return 0, connect.NewError(
			connect.CodeUnauthenticated,
			fmt.Errorf("missing TLS info"),
		)
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return 0, connect.NewError(
			connect.CodeUnauthenticated,
			fmt.Errorf("missing client certificate"),
		)
	}

	ia, err := cppki.ExtractIA(tlsInfo.State.PeerCertificates[0].Subject)
	if err != nil {
		return 0, connect.NewError(
			connect.CodeInvalidArgument,
			fmt.Errorf("invalid client certificate"),
		)
	}
	return ia, nil
}

type ASAccountManager struct {
	db                  *AccountDB
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
	user := s.db.GetASUser(ia)
	if user == nil {
		user = &ASUser{
			IA:           ia,
			TokenVersion: 0,
		}
		if !s.db.CreateNonExistingASUser(user) {
			return nil, serrors.New("register failed")
		}
	}
	return &connect.Response[hummingbird.RegisterASResponse]{
		Msg: &hummingbird.RegisterASResponse{
			JwtPublisher:  publisherToken,
			JwtRedemption: redemptionToken,
		},
	}, nil
}

func NewASAccountManager(db *AccountDB, regService *registration.Service) *ASAccountManager {
	return &ASAccountManager{
		db:                  db,
		registrationService: regService,
	}
}

/*
	func (s *ASTokenManager) IssueJWT(ctx context.Context, req *connect.Request[hummingbird.JWTIssuanceRequest]) (*connect.Response[hummingbird.JWTIssuanceResponse], error) {
		name, err := subjectFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		user := s.db.GetASUser(name)
		if user == nil {
			user = &ASUser{
				IA:           name,
				TokenVersion: 0,
			}
			if !s.db.CreateNonExistingASUser(user) {
				return nil, serrors.New("register failed")
			}
		}

		publisherClaims := jwt.MapClaims{
			"sub":   name.String(),
			"scope": "AssetPublisher",
			"exp":   time.Now().Add(time.Hour * 24 * 7).Unix(),
			"iat":   time.Now().Unix(),
			"ver":   user.TokenVersion,
		}
		publisherToken, err := s.signer.GenerateToken(publisherClaims)
		if err != nil {
			return nil, err
		}
		redemptionClaims := jwt.MapClaims{
			"sub":   name.String(),
			"scope": "RedemptionService",
			"exp":   time.Now().Add(time.Hour * 24 * 7).Unix(),
			"iat":   time.Now().Unix(),
			"ver":   user.TokenVersion,
		}
		redemptionToken, err := s.signer.GenerateToken(redemptionClaims)
		if err != nil {
			return nil, err
		}

		return &connect.Response[hummingbird.JWTIssuanceResponse]{
			Msg: &hummingbird.JWTIssuanceResponse{
				JwtPublisher:  publisherToken,
				JwtRedemption: redemptionToken,
			},
		}, nil
	}
*/
func (s *ASAccountManager) ResetJWT(ctx context.Context, req *connect.Request[hummingbird.JWTResetRequest]) (*connect.Response[hummingbird.JWTResetResponse], error) {
	name, err := subjectFromCtx(ctx)
	if err != nil {
		return nil, err
	}
	user := s.db.GetASUser(name)
	if user != nil {
		user.TokenVersion++
	}
	return &connect.Response[hummingbird.JWTResetResponse]{Msg: &hummingbird.JWTResetResponse{}}, nil
}
