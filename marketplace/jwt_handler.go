package marketplace

import (
	"crypto/ed25519"
	"fmt"

	"github.com/golang-jwt/jwt"
)

type Signer struct {
	privKey ed25519.PrivateKey
}

func NewSigner(privKey ed25519.PrivateKey) *Signer {
	return &Signer{
		privKey: privKey,
	}
}

func (s *Signer) GenerateToken(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(*&jwt.SigningMethodEdDSA, claims)
	signedToken, err := token.SignedString(s.privKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

type Verifier struct {
	pubKey ed25519.PublicKey
}

func NewVerifier(pubKey ed25519.PublicKey) *Verifier {
	return &Verifier{
		pubKey: pubKey,
	}
}

func (v *Verifier) VerifyToken(token string) (*jwt.Token, error) {
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// Always check signing method!
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return v.pubKey, nil
	})
	if err != nil {
		return nil, err
	}
	return parsedToken, nil
}
