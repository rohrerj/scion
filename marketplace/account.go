package marketplace

import (
	"context"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt"
	"github.com/scionproto/scion/pkg/addr"
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

type ASTokenManager struct {
	signer *Signer
	db     *AccountDB
}

func NewASTokenManager(signer *Signer, db *AccountDB) *ASTokenManager {
	return &ASTokenManager{
		signer: signer,
		db:     db,
	}
}

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

func (s *ASTokenManager) ResetJWT(ctx context.Context, req *connect.Request[hummingbird.JWTResetRequest]) (*connect.Response[hummingbird.JWTResetResponse], error) {
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
