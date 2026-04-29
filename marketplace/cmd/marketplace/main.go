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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/marketplace"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
)

func main() {
	if err := realMain(context.Background()); err != nil {
		fmt.Println(err)
	}
}

func realMain(ctx context.Context) error {
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatal(err)
	}

	service := marketplace.NewService()
	redemptionServer := &marketplace.Server{}
	service.RegisterRedemptionServerPeer(ctx, redemptionServer.NewRedemptionServerPeer(addr.MustParseIA("1-ff00:0:110")))
	service.RegisterRedemptionServerPeer(ctx, redemptionServer.NewRedemptionServerPeer(addr.MustParseIA("1-ff00:0:111")))
	service.RegisterRedemptionServerPeer(ctx, redemptionServer.NewRedemptionServerPeer(addr.MustParseIA("1-ff00:0:112")))

	mux := http.NewServeMux()
	path, handler := hummingbirdconnect.NewMarketplaceServiceHandler(service, connect.WithInterceptors(marketplace.NewAuthInterceptor()))
	path2, handler2 := hummingbirdconnect.NewRedemptionServiceHandler(redemptionServer, connect.WithInterceptors(marketplace.NewAuthInterceptor()))

	mux.Handle(path, handler)
	mux.Handle(path2, handler2)

	server := &http.Server{
		Addr:    ":8888",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	log.Printf("HTTPS server running on %s\n", ":8888")

	log.Fatal(server.ListenAndServeTLS("", ""))
	return nil
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
