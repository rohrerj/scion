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
	publisherToken      *JwtToken
	redemptionToken     *JwtToken
}

func NewTokenRenwer(accountApiUrl string, getClientCertifcate func(reqInfo *tls.CertificateRequestInfo) (*tls.Certificate, error),
	publisherToken *JwtToken, redemptionToken *JwtToken) *TokenRenewer {
	return &TokenRenewer{
		accountAPIUrl:       accountApiUrl,
		getClientCertifcate: getClientCertifcate,
		publisherToken:      publisherToken,
		redemptionToken:     redemptionToken,
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

	renewToken := func() (string, string, error) {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
		defer cancelF()
		resp, err := client.IssueJWT(ctx, &connect.Request[hummingbird.JWTIssuanceRequest]{})
		if err != nil {
			return "", "", err
		}
		publisherTokenString := resp.Msg.JwtPublisher
		publisherClaims := jwt.MapClaims{}
		_, _, err = parser.ParseUnverified(publisherTokenString, publisherClaims)
		if err != nil {
			return "", "", err
		}

		redemptionTokenString := resp.Msg.JwtRedemption
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
