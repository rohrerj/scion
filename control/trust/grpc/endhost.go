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

package grpc

import (
	"context"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	ehpb "github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
	"google.golang.org/grpc/peer"
)

type EndhostServer struct {
	// Provider provides the trust material.
	Provider trust.Provider
	// IA is the local ISD-AS.
	IA addr.IA
}

func (s EndhostServer) Chains(ctx context.Context,
	req *ehpb.ListChainsRequest) (*ehpb.ListChainResponse, error) {

	peer, _ := peer.FromContext(ctx)
	validity := cppki.Validity{
		NotAfter:  time.Unix(int64(req.AtLeastValidUntil), 0),
		NotBefore: time.Unix(int64(req.AtLeastValidSince), 0),
	}
	rep := &ehpb.ListChainResponse{}
	for _, subject := range req.Subjects {
		query := trust.ChainQuery{
			IA:           addr.IA(subject.IsdAs),
			SubjectKeyID: subject.SubjectKeyId,
			Validity:     validity,
		}
		chains, err := s.Provider.GetChains(ctx, query, trust.AllowInactive(), trust.Client(peer.Addr))
		if err != nil {
			return nil, err
		}
		chainRep := &ehpb.ChainsResponse{
			Chains: make([]*ehpb.Chain, 0, len(chains)),
		}
		for _, chain := range chains {
			chainRep.Chains = append(chainRep.Chains, &ehpb.Chain{
				AsCert: chain[0].Raw,
				CaCert: chain[1].Raw,
			})
		}
		rep.ListChain = append(rep.ListChain, chainRep)
	}
	return rep, nil
}

func (s *EndhostServer) TRC(ctx context.Context, req *ehpb.TRCRequest) (*ehpb.TRCResponse, error) {
	peer, _ := peer.FromContext(ctx)
	if req.Isd > uint32(addr.MaxISD) {
		return nil, serrors.New("requested ISD not in range",
			"max", addr.MaxISD, "isd", req.Isd)
	}
	trcID := cppki.TRCID{
		ISD:    addr.ISD(req.Isd),
		Base:   scrypto.Version(req.Base),
		Serial: scrypto.Version(req.Serial),
	}

	if !(trcID.Base.IsLatest() && trcID.Serial.IsLatest()) {
		if err := trcID.Validate(); err != nil {
			return nil, err
		}
	} else if trcID.ISD == 0 {
		return nil, cppki.ErrWildcardISD
	}
	trc, err := s.Provider.GetSignedTRC(ctx, trcID, trust.AllowInactive(), trust.Client(peer.Addr))
	if err != nil {
		return nil, err
	}
	return &ehpb.TRCResponse{
		Trc: trc.Raw,
	}, nil
}
