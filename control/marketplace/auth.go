package marketplace

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt"
	"github.com/scionproto/scion/pkg/addr"
)

var jwtSecret = []byte("test-key")

func createToken(ia addr.IA) (string, error) {
	claims := jwt.MapClaims{
		"sub":   ia.String(),
		"scope": "PublishAsset,RedeemAssetAS",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

type AuthInterceptor struct {
	token string
}

func NewAuthInterceptor(token string) *AuthInterceptor {
	return &AuthInterceptor{token: token}
}

func (a *AuthInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("Authorization", "Bearer "+a.token)
		return next(ctx, req)
	}
}

func (a *AuthInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {

	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)

		conn.RequestHeader().Set("Authorization", "Bearer "+a.token)

		return conn
	}
}

func (a *AuthInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}
