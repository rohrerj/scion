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
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/endhost"
	"github.com/scionproto/scion/pkg/private/serrors"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
)

type Service struct {
	challenges        map[string]Challenge
	challengeLifetime time.Duration
	trustProvider     trust.Provider
	jwtSigner         *Signer
	mtx               sync.RWMutex
}
type fetcher struct {
	trustService *endhost.TrustService
}

func chainToCerts(c *endhost.Chain) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	asCert, err := x509.ParseCertificate(c.AsCert)
	if err != nil {
		return nil, serrors.Wrap("parsing AS certificate", err)
	}
	caCert, err := x509.ParseCertificate(c.CaCert)
	if err != nil {
		return nil, serrors.Wrap("parsing CA certificate", err)
	}
	chain = append(chain, asCert, caCert)
	return chain, nil
}

func (f *fetcher) Chains(ctx context.Context, req trust.ChainQuery, _ net.Addr) ([][]*x509.Certificate, error) {
	chains, err := f.trustService.ListChains(ctx, []endhost.Subject{
		{
			IA:           req.IA,
			SubjectKeyId: req.SubjectKeyID,
		},
	}, req.Validity)
	if err != nil {
		return nil, err
	}
	certs := make([][]*x509.Certificate, 0, 1)
	for _, chain := range chains.Chains {
		c, err := chainToCerts(&chain)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func (f *fetcher) TRC(ctx context.Context, id cppki.TRCID, server net.Addr) (cppki.SignedTRC, error) {
	raw, err := f.trustService.TRC(ctx, uint32(id.ISD), uint64(id.Base), uint64(id.Serial))
	trc, err := cppki.DecodeSignedTRC(raw)
	if err != nil {
		return cppki.SignedTRC{}, serrors.WrapNoStack("parsing TRC", err)
	}
	return trc, nil
}

type recurser struct {
}

func (r *recurser) AllowRecursion(peer net.Addr) error {
	return nil
}

func NewService(connector *endhost.Connector, trustDB trust.DB, signer *Signer) *Service {
	return &Service{
		challenges:        make(map[string]Challenge),
		challengeLifetime: time.Minute,
		trustProvider: trust.FetchingProvider{
			DB: trustDB,
			Fetcher: &fetcher{
				trustService: connector.TrustService,
			},
			Router: trust.LocalRouter{
				IA: connector.Topology.LocalIA,
			},
			Recurser: &recurser{},
		},
		jwtSigner: signer,
	}
}

type Challenge struct {
	ID    string
	IA    addr.IA
	Nonce []byte
}

func (s *Service) CreateChallenge(ctx context.Context, ia addr.IA) (string, []byte, error) {
	nonce := make([]byte, 32)
	challengeID := make([]byte, 32)
	rand.Read(nonce)
	rand.Read(challengeID)
	challengeIDString := hex.EncodeToString(challengeID)

	c := Challenge{
		ID:    challengeIDString,
		IA:    ia,
		Nonce: nonce,
	}
	s.challengeMapOp(func(m map[string]Challenge) error {
		m[c.ID] = c
		return nil
	})
	return challengeIDString, nonce, nil
}

func (s *Service) RegisterAS(ctx context.Context, challengeID string, signedMsg *cryptopb.SignedMessage) (string, string, addr.IA, error) {
	c, found := s.challengeGet(challengeID)
	if !found {
		return "", "", 0, serrors.New("no challenge found for provided ID")
	}
	now := time.Now()
	verifier := &trust.Verifier{
		BoundIA: c.IA,
		Engine:  s.trustProvider,
		BoundValidity: cppki.Validity{
			NotBefore: now,
			NotAfter:  now,
		},
	}
	msg, err := verifier.Verify(ctx, signedMsg)
	if err != nil {
		return "", "", 0, err
	}
	if slices.Compare(msg.Body, c.Nonce) != 0 {
		return "", "", 0, serrors.New("wrong challenge")
	}
	publisherToken, err := s.jwtSigner.GenerateToken(jwt.MapClaims{
		"sub":   c.IA.String(),
		"scope": ScopeAssetPublisher,
		"exp":   now.Add(time.Hour * 24 * 7).Unix(),
		"iat":   now.Unix(),
	})
	if err != nil {
		return "", "", 0, err
	}
	redemptionToken, err := s.jwtSigner.GenerateToken(jwt.MapClaims{
		"sub":   c.IA.String(),
		"scope": ScopeRedemptionService,
		"exp":   now.Add(time.Hour * 24 * 7).Unix(),
		"iat":   now.Unix(),
	})
	if err != nil {
		return "", "", 0, err
	}
	return publisherToken, redemptionToken, c.IA, nil
}

func (s *Service) challengeGet(id string) (Challenge, bool) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	c, ok := s.challenges[id]
	return c, ok
}

func (s *Service) challengeMapOp(f func(map[string]Challenge) error) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return f(s.challenges)
}
