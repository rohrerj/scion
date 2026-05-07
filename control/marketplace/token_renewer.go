package marketplace

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
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
	accountAPIUrl       string
	getClientCertifcate func(reqInfo *tls.CertificateRequestInfo) (*tls.Certificate, error)
	token               *JwtToken
}

func NewTokenRenwer(accountApiUrl string, getClientCertifcate func(reqInfo *tls.CertificateRequestInfo) (*tls.Certificate, error),
	token *JwtToken) *TokenRenewer {
	return &TokenRenewer{
		accountAPIUrl:       accountApiUrl,
		getClientCertifcate: getClientCertifcate,
		token:               token,
	}
}

func (t *TokenRenewer) InitTokenRenewer() error {
	client := hummingbirdconnect.NewAccountServiceClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				GetClientCertificate: t.getClientCertifcate,
				InsecureSkipVerify:   true,
			},
		},
	}, t.accountAPIUrl)
	parser := jwt.Parser{}

	renewToken := func() (string, error) {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
		defer cancelF()
		resp, err := client.IssueJWT(ctx, &connect.Request[hummingbird.JWTIssuanceRequest]{})
		if err != nil {
			return "", err
		}
		tokenString := resp.Msg.Jwt

		claims := jwt.MapClaims{}

		_, _, err = parser.ParseUnverified(tokenString, claims)
		if err != nil {
			return "", err
		}
		return tokenString, nil
	}
	for {
		tokenString, err := renewToken()
		if err != nil {
			log.Debug("Error while requesting JWT token from marketplace", "err", err)
			time.Sleep(time.Second * 10)
			continue
		}
		t.token.Set(tokenString)
		time.Sleep(time.Minute * 10)
	}
}
