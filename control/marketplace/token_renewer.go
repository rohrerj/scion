package marketplace

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	cstrust "github.com/scionproto/scion/control/trust"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird/registration"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
)

type JwtToken struct {
	token string
	mtx   sync.RWMutex
}

func (t *JwtToken) String() string {
	t.mtx.RLock()
	defer t.mtx.RUnlock()
	return t.token
}
func (t *JwtToken) Set(token string) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	t.token = token
}

type TokenRenewer struct {
	accountAPIUrl   string
	tlsCertLoader   cstrust.TLSCertificateLoader
	cert            *tls.Certificate
	publisherToken  *JwtToken
	redemptionToken *JwtToken
	ia              addr.IA
}

func NewTokenRenwer(accountApiUrl string, ia addr.IA, tlsCertLoader cstrust.TLSCertificateLoader,
	publisherToken *JwtToken, redemptionToken *JwtToken) *TokenRenewer {
	return &TokenRenewer{
		accountAPIUrl:   accountApiUrl,
		tlsCertLoader:   tlsCertLoader,
		publisherToken:  publisherToken,
		redemptionToken: redemptionToken,
		ia:              ia,
	}
}

func (t *TokenRenewer) InitTokenRenewer() error {
	client := hummingbirdconnect.NewAccountServiceClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}, t.accountAPIUrl)
	parser := jwt.Parser{}
	renewToken := func() (string, string, error) {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
		defer cancelF()
		regClient := registration.NewClient(client)
		signers, err := t.tlsCertLoader.SignerGen.Generate(ctx)
		if err != nil {
			return "", "", err
		}
		now := time.Now()
		signer, err := trust.LastExpiring(signers, cppki.Validity{
			NotBefore: now,
			NotAfter:  now,
		})
		if err != nil {
			return "", "", err
		}
		publisherTokenString, redemptionTokenString, err := regClient.Register(ctx, signer)
		if err != nil {
			return "", "", err
		}
		publisherClaims := jwt.MapClaims{}
		_, _, err = parser.ParseUnverified(publisherTokenString, publisherClaims)
		if err != nil {
			return "", "", err
		}
		redemptionClaims := jwt.MapClaims{}
		_, _, err = parser.ParseUnverified(redemptionTokenString, redemptionClaims)
		if err != nil {
			return "", "", err
		}
		return publisherTokenString, redemptionTokenString, nil
	}
	for {
		publisherToken, redemptionToken, err := renewToken()
		if err != nil {
			log.Debug("Error while requesting JWT token from marketplace", "err", err)
			time.Sleep(time.Second * 10)
			continue
		}
		t.publisherToken.Set(publisherToken)
		t.redemptionToken.Set(redemptionToken)
		time.Sleep(time.Minute * 10)
	}
}
