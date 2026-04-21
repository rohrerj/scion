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
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/patrickmn/go-cache"
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
	fetchedChains map[string][]Chain
	mtx           sync.Mutex
}

func (p *trustServiceProvider) NotifyTRC(ctx context.Context, id cppki.TRCID, opts ...trust.Option) error {
	// For simplicity, do nothing as the endhost provides verified chains
	return nil
}

func (p *trustServiceProvider) GetChains(ctx context.Context, query trust.ChainQuery, opts ...trust.Option) ([][]*x509.Certificate, error) {
	subjectKey := fmt.Sprintf("chain-%s-%x", query.IA, query.SubjectKeyID)
	chains, found := p.fetchedChains[subjectKey]
	if !found {
		return nil, serrors.New("no chains found for subject")
	}
	var result [][]*x509.Certificate
	var chain []*x509.Certificate
	for _, c := range chains {
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
	verifier   trust.Verifier
	cache      *cache.Cache
	provider   *trustServiceProvider
}

func NewTrustService(url string) *TrustService {
	provider := &trustServiceProvider{
		fetchedChains: make(map[string][]Chain),
	}
	t := &TrustService{
		url: url,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		provider: provider,
		verifier: trust.Verifier{
			Engine: provider,
			Cache:  cache.New(time.Minute, time.Minute),
		},
	}
	provider.ts = t
	return t
}

type Subject struct {
	IA           addr.IA
	SubjectKeyId []byte
}

type Chains struct {
	Chains []Chain
}

type Chain struct {
	AsCert  []byte
	CaCert  []byte
	Subject Subject
}

func (t *TrustService) ListChains(ctx context.Context, subjects []Subject) (*Chains, error) {
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
	chains := &Chains{
		Chains: make([]Chain, 0, len(repChains.Msg.Chains)),
	}
	for _, chain := range repChains.Msg.Chains {
		chains.Chains = append(chains.Chains, Chain{
			Subject: Subject{
				IA:           addr.IA(chain.Subject.IsdAs),
				SubjectKeyId: chain.Subject.SubjectKeyId,
			},
			AsCert: chain.AsCert,
			CaCert: chain.CaCert,
		})
	}
	return chains, nil
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

// VerifyPathSegments extracts the subjects from all AS entries in all provided path segments,
// performs a ListChains request to obtain the corresponding chains and stores them in memory.
// It then uses the verifer to perform the segment verification where it will use chains either
// from the verifier cache or the fetched chains.
// An error slice of length equal to the number of segments is returned where each entry is nil
// if the corresponding segment is valid or contains the verification error if it is not valid.
func (t *TrustService) VerifyPathSegments(ctx context.Context, segments []*seg.PathSegment) ([]error, error) {
	t.provider.mtx.Lock()
	defer t.provider.mtx.Unlock()
	addedSubjects := make(map[string]struct{})
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
			subjectKey := fmt.Sprintf("chain-%s-%x", ia, keyID.SubjectKeyId)
			if _, found := addedSubjects[subjectKey]; !found {
				subjects = append(subjects, Subject{
					IA:           ia,
					SubjectKeyId: keyID.SubjectKeyId,
				})
				addedSubjects[subjectKey] = struct{}{}
			}
		}
	}
	listChains, err := t.ListChains(ctx, subjects)
	if err != nil {
		return nil, serrors.Wrap("on list chains", err)
	}
	clear(t.provider.fetchedChains)
	for _, chain := range listChains.Chains {
		subjectKey := fmt.Sprintf("chain-%s-%x", chain.Subject.IA, chain.Subject.SubjectKeyId)
		currentSlice, found := t.provider.fetchedChains[subjectKey]
		if found {
			currentSlice = append(currentSlice, chain)
		} else {
			t.provider.fetchedChains[subjectKey] = []Chain{chain}
		}
	}
	verificationErrors := make([]error, len(segments))
	for i, segment := range segments {
		if err := segment.Verify(ctx, t.verifier); err != nil {
			verificationErrors[i] = err
		}
	}
	return verificationErrors, nil
}
