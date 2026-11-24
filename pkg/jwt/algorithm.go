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

package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// AlgorithmResolver maps a public key to the JWS algorithm that must be used
// with it. It returns ok=false if the key is not handled by this resolver.
type AlgorithmResolver func(pub crypto.PublicKey) (alg jwa.SignatureAlgorithm, ok bool)

var (
	resolversMu sync.RWMutex
	resolvers   = []AlgorithmResolver{classicalResolver}
)

// RegisterAlgorithm adds support for additional key types. Algorithms that
// jwx does not implement natively (e.g., post-quantum schemes such as ML-DSA)
// must additionally be registered with jwx via jws.RegisterSigner and
// jws.RegisterVerifier.
func RegisterAlgorithm(r AlgorithmResolver) {
	resolversMu.Lock()
	defer resolversMu.Unlock()
	resolvers = append(resolvers, r)
}

func algorithmFor(pub crypto.PublicKey) (jwa.SignatureAlgorithm, error) {
	resolversMu.RLock()
	defer resolversMu.RUnlock()
	for _, r := range resolvers {
		if alg, ok := r(pub); ok {
			return alg, nil
		}
	}
	return jwa.EmptySignatureAlgorithm(), serrors.New("unsupported key type")
}

func classicalResolver(pub crypto.PublicKey) (jwa.SignatureAlgorithm, bool) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return jwa.EdDSA(), true
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return jwa.ES256(), true
		case elliptic.P384():
			return jwa.ES384(), true
		case elliptic.P521():
			return jwa.ES512(), true
		}
	case *rsa.PublicKey:
		return jwa.PS256(), true
	}
	return jwa.EmptySignatureAlgorithm(), false
}
