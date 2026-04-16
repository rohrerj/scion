// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endhost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/proto/endhost/v1/endhostconnect"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/trust"
)

type trustServiceProvider struct {
	ts            *TrustService
	fetchedChains map[subject2]Chains
}
type subject2 struct {
	kedId string
	ia    addr.IA
}

func (p *trustServiceProvider) NotifyTRC(ctx context.Context, id cppki.TRCID, opts ...trust.Option) error {
	// For simplicity, do nothing as the endhost provides verified chains
	return nil
}

func (p *trustServiceProvider) GetChains(ctx context.Context, query trust.ChainQuery, opts ...trust.Option) ([][]*x509.Certificate, error) {
	subject := subject2{ia: query.IA, kedId: string(query.SubjectKeyID)}
	chains, found := p.fetchedChains[subject]
	if !found {
		return nil, serrors.New("no chains found for subject")
	}
	var result [][]*x509.Certificate
	var chain []*x509.Certificate
	for _, c := range chains.Chains {
		asCert, err := x509.ParseCertificate(c.AsCert)
		if err != nil {
			return nil, serrors.Wrap("parsing AS certificate", err)
		}
		caCert, err := x509.ParseCertificate(c.CaCert)
		if err != nil {
			return nil, serrors.Wrap("parsing CA certificate", err)
		}
		chain = append(chain, asCert, caCert)
	}
	result = append(result, chain)
	return result, nil
}

func (p *trustServiceProvider) GetSignedTRC(ctx context.Context, id cppki.TRCID, opts ...trust.Option) (cppki.SignedTRC, error) {
	trcBytes, err := p.ts.TRC(ctx, uint32(id.ISD), uint64(id.Base), uint64(id.Serial))
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	return cppki.DecodeSignedTRC(trcBytes)
}

type TrustService struct {
	url        string
	httpClient *http.Client
}

func NewTrustService(url string) *TrustService {
	t := &TrustService{
		url: url,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
	return t
}

type Subject struct {
	IA           addr.IA
	SubjectKeyId []byte
}

type Chain struct {
	AsCert []byte
	CaCert []byte
}
type Chains struct {
	Chains  []Chain
	Subject Subject
}

func (t *TrustService) ListChains(ctx context.Context, subjects []Subject) ([]Chains, error) {
	client := endhostconnect.NewTrustServiceClient(t.httpClient, t.url)
	req := &connect.Request[endhost.ListChainsRequest]{
		Msg: &endhost.ListChainsRequest{
			Subjects:          make([]*endhost.Subject, 0, len(subjects)),
			AtLeastValidUntil: 0,
			AtLeastValidSince: 0,
		},
	}
	for _, subject := range subjects {
		req.Msg.Subjects = append(req.Msg.Subjects, &endhost.Subject{
			IsdAs:        uint64(subject.IA),
			SubjectKeyId: subject.SubjectKeyId,
		})
	}
	repChains, err := client.ListChains(ctx, req)
	if err != nil {
		return nil, serrors.Wrap("on ListChains", err)
	}
	rep := make([]Chains, 0, len(repChains.Msg.ListChain))
	for _, chains := range repChains.Msg.ListChain {
		rep_chains := Chains{
			Chains: make([]Chain, 0, len(chains.Chains)),
			Subject: Subject{
				IA:           addr.IA(chains.Subject.IsdAs),
				SubjectKeyId: chains.Subject.SubjectKeyId,
			},
		}
		for _, chain := range chains.Chains {
			rep_chains.Chains = append(rep_chains.Chains, Chain{
				AsCert: chain.AsCert,
				CaCert: chain.CaCert,
			})
		}
		rep = append(rep, rep_chains)
	}
	return rep, nil
}

func (t *TrustService) TRC(ctx context.Context, isd uint32, base uint64, serial uint64) ([]byte, error) {
	client := endhostconnect.NewTrustServiceClient(t.httpClient, t.url)
	rep, err := client.GetTrc(ctx, &connect.Request[endhost.TRCRequest]{
		Msg: &endhost.TRCRequest{
			Isd:    isd,
			Base:   base,
			Serial: serial,
		},
	})
	if err != nil {
		return nil, serrors.Wrap("on TRC", err)
	}
	return rep.Msg.Trc, nil
}

func (t *TrustService) VerifyPathSegments(ctx context.Context, segments []*seg.PathSegment) ([]error, error) {
	provider := &trustServiceProvider{
		ts:            t,
		fetchedChains: map[subject2]Chains{},
	}
	verifier := trust.Verifier{
		Engine: provider,
	}
	addedSubjects := make(map[subject2]struct{})
	subjects := make([]Subject, 0, 1)
	for _, segment := range segments {
		for _, asEntry := range segment.ASEntries {
			hdr, err := signed.ExtractUnverifiedHeader(asEntry.Signed)
			if err != nil {
				return nil, serrors.Wrap("extracting unverified header", err)
			}
			var keyID cppb.VerificationKeyID
			if err := proto.Unmarshal(hdr.VerificationKeyID, &keyID); err != nil {
				return nil, serrors.Wrap("parsing verification key ID", err)
			}
			if len(keyID.SubjectKeyId) == 0 {
				return nil, serrors.Wrap("subject key ID must be set", err)
			}
			ia := addr.IA(keyID.IsdAs)
			if ia.IsWildcard() {
				return nil, serrors.New("ISD-AS must not contain wildcard", "isd_as", ia)
			}
			s := string(keyID.SubjectKeyId)
			key := subject2{
				kedId: s,
				ia:    ia,
			}
			if _, found := addedSubjects[key]; !found {
				subjects = append(subjects, Subject{
					IA:           ia,
					SubjectKeyId: keyID.SubjectKeyId,
				})
				addedSubjects[key] = struct{}{}
			}
		}
	}
	listChains, err := t.ListChains(ctx, subjects)
	if err != nil {
		return nil, serrors.Wrap("on list chains", err)
	}
	for _, chains := range listChains {
		provider.fetchedChains[subject2{
			kedId: string(chains.Subject.SubjectKeyId),
			ia:    chains.Subject.IA,
		}] = chains
	}
	verificationErrors := make([]error, len(segments))
	for i, segment := range segments {
		if err := segment.Verify(ctx, &verifier); err != nil {
			verificationErrors[i] = err
		}
	}
	return verificationErrors, nil
}
