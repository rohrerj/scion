package marketplace

import (
	"context"

	"connectrpc.com/connect"
)

type AuthInterceptor struct {
	token *JwtToken
}

func NewAuthInterceptor(token *JwtToken) *AuthInterceptor {
	return &AuthInterceptor{token: token}
}

func (a *AuthInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("Authorization", "Bearer "+a.token.String())
		return next(ctx, req)
	}
}

func (a *AuthInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {

	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)

		conn.RequestHeader().Set("Authorization", "Bearer "+a.token.String())

		return conn
	}
}

func (a *AuthInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}
