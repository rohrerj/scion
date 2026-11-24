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
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignVerify(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rs, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, otherEd, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keys := []crypto.Signer{ed, ec, rs}
	var pubs []crypto.PublicKey
	for _, k := range keys {
		pubs = append(pubs, k.Public())
	}
	multi, err := NewVerifier(pubs...)
	require.NoError(t, err)
	wrong, err := NewVerifier(otherEd.Public())
	require.NoError(t, err)

	for _, k := range keys {
		s, err := NewSigner(k)
		require.NoError(t, err)
		t.Run(s.Algorithm().String(), func(t *testing.T) {
			tok, err := s.GenerateToken(map[string]any{"sub": "test"})
			require.NoError(t, err)

			single, err := NewVerifier(k.Public())
			require.NoError(t, err)
			parsed, err := single.VerifyToken(tok)
			require.NoError(t, err)
			sub, ok := parsed.Subject()
			require.True(t, ok)
			require.Equal(t, "test", sub)

			_, err = multi.VerifyToken(tok)
			require.NoError(t, err)

			_, err = wrong.VerifyToken(tok)
			require.Error(t, err)
		})
	}
}

func TestUnsupportedKey(t *testing.T) {
	_, err := NewVerifier("not a key")
	require.Error(t, err)
}
