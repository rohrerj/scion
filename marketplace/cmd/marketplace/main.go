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
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/marketplace"
	"github.com/scionproto/scion/marketplace/webapp"
	libconnect "github.com/scionproto/scion/pkg/connect"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/endhost/v1/endhostconnect"
	"github.com/scionproto/scion/pkg/proto/hummingbird/v1/hummingbirdconnect"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/app/appnet"
	"github.com/scionproto/scion/private/app/launcher"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
)

const APIMajorVersion = uint64(0)
const APIMinorVersion = uint64(1)

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
		return err
	}
	signingPubKey, signingPrivKey, err := getJwtKeys()
	if err != nil {
		return err
	}
	jwtSigner := marketplace.NewSigner(signingPrivKey)
	jwtVerifier := marketplace.NewVerifier(signingPubKey)
	trustDB, err := storage.NewInMemoryTrustStorage()
	if err != nil {
		return err
	}
	_, err = trust.LoadTRCs(context.Background(), path.Join(globalCfg.General.ConfigDir, "certs"), trustDB)
	if err != nil {
		return err
	}
	var endhostAPI string
	for _, k := range topo.EndhostAPI() {
		endhostAPI = k.Url
		break
	}
	accountDB := marketplace.NewAccountDB()
	trustDB = marketplace.FromTrustDB(trustDB, endhostconnect.NewTrustServiceClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}, endhostAPI))

	trustVerifer := trust.NewTLSCryptoVerifier(trustDB)

	service := marketplace.NewService(&marketplace.MarketplaceInfo{
		ApiMajorVersion:           APIMajorVersion,
		ApiMinorVersion:           APIMinorVersion,
		Currency:                  globalCfg.Marketplace.Currency,
		StatisticsTimeGranularity: time.Duration(globalCfg.Marketplace.StatisticsTimeGranularity) * time.Second,
	})

	mux := http.NewServeMux()
	apiPath1, handler1 := hummingbirdconnect.NewMarketplaceServiceHandler(service, connect.WithInterceptors(marketplace.NewAuthInterceptor(jwtVerifier, accountDB)))
	apiPath2, handler2 := hummingbirdconnect.NewRedemptionServiceHandler(service, connect.WithInterceptors(marketplace.NewAuthInterceptor(jwtVerifier, accountDB)))

	mux.Handle(apiPath1, handler1)
	mux.Handle(apiPath2, handler2)

	server := &http.Server{
		Addr:    globalCfg.Marketplace.APIAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	accountPath, accountHandler := hummingbirdconnect.NewAccountServiceHandler(marketplace.NewASTokenManager(jwtSigner, accountDB))

	accountMux := http.NewServeMux()
	webapp.Init(jwtSigner, accountDB, accountMux)
	accountMux.Handle(accountPath, libconnect.AttachPeer(accountHandler))

	accountServer := &http.Server{
		Addr:    globalCfg.Marketplace.AccountAddr,
		Handler: accountMux,
		TLSConfig: &tls.Config{
			ClientAuth:   tls.RequestClientCert,
			Certificates: []tls.Certificate{cert},
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return nil
				}
				return trustVerifer.VerifyClientCertificate(rawCerts, verifiedChains)
			},
		},
	}
	g := &errgroup.Group{}
	g.Go(func() error {
		return server.ListenAndServeTLS("", "")
	})
	g.Go(func() error {
		return accountServer.ListenAndServeTLS("", "")
	})
	log.Info(fmt.Sprintf("HTTPS server running on %s and account management on %s\n", globalCfg.Marketplace.APIAddr, globalCfg.Marketplace.AccountAddr))
	err = func() error {
		if globalCfg.Marketplace.SCIONAPIAddr != "" {
			err = StartSCIONServer(ctx, globalCfg.Marketplace.SCIONAPIAddr, g, trustVerifer, &cert, mux)
			if err != nil {
				return err
			}
		}
		if globalCfg.Marketplace.SCIONAccountAddr != "" {
			// TODO: this part does not fully work yet, investigate what additional changes are necessary
			err = StartSCIONServer(ctx, globalCfg.Marketplace.SCIONAccountAddr, g, trustVerifer, &cert, accountMux)
			if err != nil {
				return err
			}
		}
		return nil
	}()
	if err != nil {
		log.Error("Error starting SCION server", "err", err)
	}

	g.Wait()
	return nil
}

func StartSCIONServer(ctx context.Context, addrString string, g *errgroup.Group, trustVerifier *trust.TLSCryptoVerifier, cert *tls.Certificate, mux *http.ServeMux) error {
	topoFile := path.Join(globalCfg.General.ConfigDir, "topology.json")
	addr, err := net.ResolveUDPAddr("udp", addrString)
	if err != nil {
		return err
	}

	topoLoader, err := topology.NewLoader(topology.LoaderCfg{
		File: topoFile,
	})
	if err != nil {
		return err
	}
	portRangeStart, portRangeEnd := topoLoader.PortRange()

	nc := appnet.NetworkConfig{
		Topology: snet.Topology{
			LocalIA: topoLoader.IA(),
			Interface: func(u uint16) (netip.AddrPort, bool) {
				ifid, found := topoLoader.InterfaceInfoMap()[iface.ID(u)]
				if !found {
					return netip.AddrPort{}, false
				}
				return ifid.InternalAddr, true
			},
			PortRange: snet.TopologyPortRange{
				Start: portRangeStart,
				End:   portRangeEnd,
			},
		},
		IA: topoLoader.IA(),
		QUIC: appnet.QUIC{
			TLSVerifier: trustVerifier,
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return cert, nil
			},
		},
		Public: addr,
		MTU:    topoLoader.MTU(),
	}
	quicStack, err := nc.QUICStack(ctx)
	if err != nil {
		return err
	}
	quicServer := grpc.NewServer(
		grpc.Creds(libgrpc.PassThroughCredentials{}),
		libgrpc.UnaryServerInterceptor(),
		libgrpc.DefaultMaxConcurrentStreams(),
	)
	grpcConns := make(chan *quic.Conn)
	g.Go(func() error {
		defer log.HandlePanic()
		listener := quicStack.Listener
		for {
			conn, err := listener.Accept(context.Background())
			if err == quic.ErrServerClosed {
				return http.ErrServerClosed
			}
			if err != nil {
				return err
			}
			go func() {
				defer log.HandlePanic()
				if conn.ConnectionState().TLS.NegotiatedProtocol != "h3" {
					grpcConns <- conn
					return
				}
				connectServer := http3.Server{
					Handler: libconnect.AttachPeer(mux),
				}
				if err := connectServer.ServeQUICConn(conn); err != nil {
					log.Debug("Error handling connectrpc connection", "err", err)
				}
			}()
		}
	})
	g.Go(func() error {
		defer log.HandlePanic()
		grpcListener := squic.NewConnListener(grpcConns, quicStack.Listener.Addr())
		if err := quicServer.Serve(grpcListener); err != nil {
			return serrors.Wrap("serving gRPC/SCION API", err)
		}
		return nil
	})
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

	if err := os.WriteFile(path.Join(globalCfg.General.ConfigDir, "signature_priv.pem"), pem.EncodeToMemory(privBlock), 0644); err != nil {
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
	if err := os.WriteFile(path.Join(globalCfg.General.ConfigDir, "signature_pub.pem"), pem.EncodeToMemory(pubBlock), 0644); err != nil {
		return err
	}

	return nil
}

func getJwtKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pubFile := path.Join(globalCfg.General.ConfigDir, "signature_pub.pem")
	privFile := path.Join(globalCfg.General.ConfigDir, "signature_priv.pem")
	if _, err := os.Stat(privFile); os.IsNotExist(err) {
		signingPubKey, signingPrivKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return signingPubKey, signingPrivKey, saveSignatureKeys(signingPubKey, signingPrivKey)
	}
	privData, err := os.ReadFile(privFile)
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

	pubData, err := os.ReadFile(pubFile)
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
