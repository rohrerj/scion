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

package registration

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/proto/hummingbird"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/trust"
)

type Client struct {
	accountClient hummingbirdconnect.AccountServiceClient
	name          string
}

func NewClient(c hummingbirdconnect.AccountServiceClient, name string) *Client {
	return &Client{
		accountClient: c,
		name:          name,
	}
}

// RegisterWithNewSigner is used if the application does not already have a trust.Signer. It loads the trcs, the certificates
// and private keys from the provided folders, generates a signer and then performs the registration steps.
// Returns the publisher JWT token, the redemption service JWT token, and the error state.
func (c *Client) RegisterWithNewSigner(ctx context.Context, ia addr.IA, trcDir string,
	certDir string, keyringDir string) (string, string, error) {

	trustDB, err := storage.NewInMemoryTrustStorage()
	if err != nil {
		return "", "", err
	}
	loader := trust.TRCLoader{
		Dir: trcDir,
		DB:  trustDB,
	}
	_, err = loader.Load(ctx)
	if err != nil {
		return "", "", err
	}
	_, err = trust.LoadChains(ctx, certDir, trustDB)
	if err != nil {
		return "", "", err
	}
	gen := trust.SignerGen{
		IA: ia,
		DB: trustDB,
		KeyRing: loadingRing{
			Dir: keyringDir,
		},
		ExtKeyUsage: x509.ExtKeyUsageClientAuth,
	}
	signers, err := gen.Generate(ctx)
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
	return c.Register(ctx, signer)
}

// Register uses the provided signer to perform the registration steps.
// Returns the publisher JWT token, the redemption service JWT token, and the error state.
func (c *Client) Register(ctx context.Context, signer trust.Signer) (string, string, error) {
	challengeResponse, err := c.accountClient.CreateChallenge(ctx, &connect.Request[hummingbird.CreateChallengeRequest]{
		Msg: &hummingbird.CreateChallengeRequest{
			Ia: uint64(signer.IA),
		},
	})
	if err != nil {
		return "", "", err
	}
	signedMsg, err := signer.Sign(ctx, challengeResponse.Msg.Challenge.Value, []byte(c.name), []byte(hummingbirdconnect.AccountServiceRegisterASProcedure))
	if err != nil {
		return "", "", err
	}
	registrationResponse, err := c.accountClient.RegisterAS(ctx, &connect.Request[hummingbird.RegisterASRequest]{
		Msg: &hummingbird.RegisterASRequest{
			Id:              challengeResponse.Msg.Challenge.Id,
			SignedChallenge: signedMsg,
		},
	})
	if err != nil {
		return "", "", err
	}
	return registrationResponse.Msg.JwtPublisher, registrationResponse.Msg.JwtRedemption, nil
}

type loadingRing struct {
	Dir string
}

// PrivateKeys loads all private keys that are in PKCS#8 format from the directory.
func (r loadingRing) PrivateKeys(ctx context.Context) ([]crypto.Signer, error) {
	files, err := filepath.Glob(filepath.Join(r.Dir, "*.key"))
	if err != nil {
		return nil, err
	}

	var signers []crypto.Signer
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			log.FromCtx(ctx).Info("Error reading key file", "file", file, "err", err)
			continue
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "PRIVATE KEY" {
			continue
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			continue
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			continue
		}
		signers = append(signers, signer)
	}
	return signers, nil
}
