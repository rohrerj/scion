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
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// Signer signs JWTs. The signature algorithm is derived from the key type.
type Signer struct {
	key crypto.Signer
	alg jwa.SignatureAlgorithm
}

// SignerFromFile loads a PKCS#8 PEM private key of any supported type.
func SignerFromFile(privateKeyFile string) (*Signer, error) {
	block, err := readPEM(privateKeyFile)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, serrors.Wrap("parsing private key", err, "file", privateKeyFile)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, serrors.New("private key cannot sign")
	}
	return NewSigner(signer)
}

func NewSigner(key crypto.Signer) (*Signer, error) {
	alg, err := algorithmFor(key.Public())
	if err != nil {
		return nil, err
	}
	return &Signer{key: key, alg: alg}, nil
}

// Algorithm returns the JWS algorithm this signer uses.
func (s *Signer) Algorithm() jwa.SignatureAlgorithm { return s.alg }

func (s *Signer) GenerateToken(claims map[string]any) (string, error) {
	builder := jwt.NewBuilder()
	for k, v := range claims {
		builder = builder.Claim(k, v)
	}
	token, err := builder.Build()
	if err != nil {
		return "", err
	}
	signed, err := jwt.Sign(token, jwt.WithKey(s.alg, s.key))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

type verificationKey struct {
	alg jwa.SignatureAlgorithm
	key crypto.PublicKey
}

// Verifier verifies JWTs against one or more trusted public keys. Accepting
// several keys allows key rotation and a gradual migration between
// algorithms (e.g., Ed25519 -> ML-DSA).
type Verifier struct {
	keys []verificationKey
}

// VerifierFromFile loads one or more PKIX PEM public keys from a file.
func VerifierFromFile(publicKeyFile string) (*Verifier, error) {
	data, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return nil, err
	}
	var pubs []crypto.PublicKey
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, serrors.Wrap("parsing public key", err, "file", publicKeyFile)
		}
		pubs = append(pubs, pub)
	}
	if len(pubs) == 0 {
		return nil, serrors.New("no PEM public key found", "file", publicKeyFile)
	}
	return NewVerifier(pubs...)
}

func NewVerifier(pubs ...crypto.PublicKey) (*Verifier, error) {
	if len(pubs) == 0 {
		return nil, serrors.New("no verification key")
	}
	v := &Verifier{}
	for _, pub := range pubs {
		alg, err := algorithmFor(pub)
		if err != nil {
			return nil, err
		}
		v.keys = append(v.keys, verificationKey{alg: alg, key: pub})
	}
	return v, nil
}

func (v *Verifier) VerifyToken(tokenStr string) (jwt.Token, error) {
	opts := make([]jwt.ParseOption, 0, len(v.keys))
	for _, k := range v.keys {
		opts = append(opts, jwt.WithKey(k.alg, k.key))
	}
	return jwt.Parse([]byte(tokenStr), opts...)
}

func readPEM(file string) (*pem.Block, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, serrors.New("failed to decode PEM", "file", file)
	}
	return block, nil
}
