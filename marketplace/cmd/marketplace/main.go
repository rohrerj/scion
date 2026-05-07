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

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	"github.com/scionproto/scion/marketplace"
	"github.com/scionproto/scion/marketplace/webapp"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
	"github.com/scionproto/scion/private/app/launcher"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
)

var globalCfg marketplace.Config

func main() {
	application := launcher.Application{
		ApplicationBase: launcher.ApplicationBase{
			TOMLConfig: &globalCfg,
			ShortName:  "SCION Daemon",
			Main:       realMain,
		},
	}
	application.Run()
}

func realMain(ctx context.Context) error {
	topo, err := topology.NewLoader(topology.LoaderCfg{
		File:      globalCfg.General.Topology(),
		Validator: &topology.DefaultValidator{},
	})
	if err != nil {
		return serrors.Wrap("creating topology loader", err)
	}
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatal(err)
	}
	signingPubKey, signingPrivKey, err := getJwtKeys()
	if err != nil {
		log.Fatal(err)
	}
	jwtSigner := marketplace.NewSigner(signingPrivKey)
	jwtVerifier := marketplace.NewVerifier(signingPubKey)
	trustDB, err := storage.NewInMemoryTrustStorage()
	if err != nil {
		return err
	}
	_, err = trust.LoadTRCs(context.Background(), "gen/marketplace/certs", trustDB)
	if err != nil {
		return err
	}
	trustDB = marketplace.FromTrustDB(trustDB, control_planeconnect.NewTrustMaterialServiceClient(&http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}, fmt.Sprintf("https://%s", topo.ControlServiceAddresses()[0].String())))

	trustVerifer := trust.NewTLSCryptoVerifier(trustDB)

	service := marketplace.NewService()

	mux := http.NewServeMux()
	path, handler := hummingbirdconnect.NewMarketplaceServiceHandler(service, connect.WithInterceptors(marketplace.NewAuthInterceptor(jwtVerifier)))
	path2, handler2 := hummingbirdconnect.NewRedemptionServiceHandler(service, connect.WithInterceptors(marketplace.NewAuthInterceptor(jwtVerifier)))

	mux.Handle(path, handler)
	mux.Handle(path2, handler2)

	iaUserRegistrationMux := http.NewServeMux()
	webapp.Init(jwtSigner, mux, iaUserRegistrationMux)

	server := &http.Server{
		Addr:    globalCfg.Marketplace.APIAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	accountServer := &http.Server{
		Addr:    globalCfg.Marketplace.AccountAddr,
		Handler: iaUserRegistrationMux,
		TLSConfig: &tls.Config{
			ClientAuth:            tls.RequireAnyClientCert,
			Certificates:          []tls.Certificate{cert},
			VerifyPeerCertificate: trustVerifer.VerifyClientCertificate,
		},
	}
	g := sync.WaitGroup{}
	g.Go(func() {
		fmt.Println(server.ListenAndServeTLS("", ""))
	})
	g.Go(func() {
		fmt.Println(accountServer.ListenAndServeTLS("", ""))
	})
	log.Printf("HTTPS server running on %s and AS user creation on %s\n", ":8888", ":8889")
	g.Wait()
	return nil
}

func saveSignatureKeys(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey) error {
	if err := os.MkdirAll("gen/marketplace", 0755); err != nil {
		return err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}

	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	if err := os.WriteFile("gen/marketplace/signature_priv.pem", pem.EncodeToMemory(privBlock), 0644); err != nil {
		return err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	if err := os.WriteFile("gen/marketplace/signature_pub.pem", pem.EncodeToMemory(pubBlock), 0644); err != nil {
		return err
	}

	return nil
}

func getJwtKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if _, err := os.Stat("gen/marketplace/signature_priv.pem"); os.IsNotExist(err) {
		signingPubKey, signingPrivKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return signingPubKey, signingPrivKey, saveSignatureKeys(signingPubKey, signingPrivKey)
	}
	privData, err := os.ReadFile("gen/marketplace/signature_priv.pem")
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(privData)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM")
	}

	privkey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	priv, ok := privkey.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("not an Ed25519 private key")
	}

	pubData, err := os.ReadFile("gen/marketplace/signature_pub.pem")
	if err != nil {
		return nil, nil, err
	}

	block, _ = pem.Decode(pubData)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	pub, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("not an Ed25519 public key")
	}

	return pub, priv, nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour * 365),

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	return cert, nil
}
