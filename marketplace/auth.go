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

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt"
)

var jwtSecret = []byte("test-key")

var methodScopes = map[string]string{
	"/proto.hummingbird.v1.MarketplaceService/PublishAsset":      "PublishAsset",
	"/proto.hummingbird.v1.MarketplaceService/SearchAssets":      "SearchAssets",
	"/proto.hummingbird.v1.MarketplaceService/BuyAssets":         "BuyAssets",
	"/proto.hummingbird.v1.MarketplaceService/FetchReservations": "FetchReservations",
	"/proto.hummingbird.v1.MarketplaceService/RedeemAsset":       "RedeemAsset",
}

func AuthInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			method := req.Spec().Procedure
			requiredScope, found := methodScopes[method]
			if !found {
				//no rules apply
				return next(ctx, req)
			}
			authHeader := req.Header().Get("Authorization")

			if !strings.HasPrefix(authHeader, "Bearer ") {
				return nil, connect.NewError(
					connect.CodeUnauthenticated,
					fmt.Errorf("missing bearer token"),
				)
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			// Parse + validate JWT
			token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtSecret, nil
			})
			if err != nil || !token.Valid {
				return nil, connect.NewError(
					connect.CodeUnauthenticated,
					fmt.Errorf("invalid token"),
				)
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return nil, connect.NewError(
					connect.CodeUnauthenticated,
					fmt.Errorf("invalid claims"),
				)
			}

			user, ok := claims["sub"].(string)
			if !ok || user == "" {
				return nil, connect.NewError(
					connect.CodeUnauthenticated,
					fmt.Errorf("missing subject"),
				)
			}
			scopeStr, ok := claims["scope"].(string)
			if !ok || scopeStr == "" {
				return nil, connect.NewError(
					connect.CodePermissionDenied,
					fmt.Errorf("missing scopes"),
				)
			}
			scopes := parseScopes(scopeStr)

			if found && !scopes[requiredScope] {
				return nil, connect.NewError(connect.CodePermissionDenied,
					fmt.Errorf("missing scope: %s", requiredScope))
			}

			ctx = context.WithValue(ctx, "user", user)

			return next(ctx, req)
		}
	}
}

func parseScopes(scopeStr string) map[string]bool {
	scopes := make(map[string]bool)
	for _, s := range strings.Split(scopeStr, ",") {
		if s != "" {
			scopes[s] = true
		}
	}
	return scopes
}
