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

package connect

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/grpc/peer"

	"github.com/opentracing/opentracing-go"
	cstrust "github.com/scionproto/scion/control/trust"
	trustmetrics "github.com/scionproto/scion/control/trust/metrics"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/pagination"
	"github.com/scionproto/scion/private/tracing"
	"github.com/scionproto/scion/private/trust"
)

type EndhostServer struct {
	// Provider provides the trust material.
	Provider trust.Provider
	// IA is the local ISD-AS.
	IA       addr.IA
	Requests metrics.Counter
}

func (e EndhostServer) ListChains(ctx context.Context,
	req *connect.Request[endhost.ListChainsRequest]) (
	*connect.Response[endhost.ListChainsResponse], error) {

	rep, err := e.chains(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}

func (e EndhostServer) GetTrc(ctx context.Context,
	req *connect.Request[endhost.GetTrcRequest]) (
	*connect.Response[endhost.GetTrcResponse], error) {

	rep, err := e.trc(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(rep), nil
}

func (s EndhostServer) chains(ctx context.Context,
	req *endhost.ListChainsRequest) (*endhost.ListChainsResponse, error) {
	labels := requestLabels{
		ReqType: trustmetrics.ListChainsReq,
		Client:  "unknown",
	}
	var peerAddr net.Addr
	if p, ok := peer.FromContext(ctx); ok {
		peerAddr = p.Addr
		labels.Client = trustmetrics.PeerToLabel(peerAddr, s.IA)
	}
	span := opentracing.SpanFromContext(ctx)
	logger := log.FromCtx(ctx)
	logger.Debug("Received chains request", "subjects", req.Subjects, "peer", peerAddr,
		"page_size", req.PageSize, "page_token", req.PageToken)

	var validity cppki.Validity
	if !(req.AtLeastValidSince == 0 && req.AtLeastValidUntil == 0) {
		validity.NotAfter = time.Unix(int64(req.AtLeastValidUntil), 0)
		validity.NotBefore = time.Unix(int64(req.AtLeastValidSince), 0)
	}
	fetch := func(ctx context.Context, subjectIdx int) ([][]*x509.Certificate, error) {
		subject := req.Subjects[subjectIdx]
		query := trust.ChainQuery{
			IA:           addr.IA(subject.IsdAs),
			SubjectKeyID: subject.SubjectKeyId,
			Validity:     validity,
		}
		chains, err := s.Provider.GetChains(ctx, query, trust.AllowInactive(),
			trust.Client(peerAddr))
		if err != nil {
			logger.Info("Unable to retrieve chains", "query", query, "err", err)
			return nil, err
		}
		return chains, nil
	}
	rep, err := cstrust.PageChains(ctx, req, fetch)
	switch {
	case errors.Is(err, pagination.ErrInvalidPageSize),
		errors.Is(err, pagination.ErrInvalidPageToken):
		logger.Debug("Invalid chains request", "peer", peerAddr, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrInternal), err)
		return nil, err
	}
	logger.Debug("Replied with chains", "count", len(rep.Chains),
		"more", rep.NextPageToken != "")
	s.updateMetric(span, labels.WithResult(trustmetrics.Success), nil)
	return rep, nil
}

func (s *EndhostServer) updateMetric(span opentracing.Span, l requestLabels, err error) {
	if s.Requests != nil {
		s.Requests.With(l.Expand()...).Add(1)
	}
	if span != nil {
		tracing.ResultLabel(span, l.Result)
		tracing.Error(span, err)
	}
}

func (s *EndhostServer) trc(ctx context.Context, req *endhost.GetTrcRequest) (*endhost.GetTrcResponse, error) {
	labels := requestLabels{
		ReqType: trustmetrics.TRCReq,
		Client:  "unknown",
	}
	var peerAddr net.Addr
	if p, ok := peer.FromContext(ctx); ok {
		peerAddr = p.Addr
		labels.Client = trustmetrics.PeerToLabel(peerAddr, s.IA)
	}
	trcID := cppki.TRCID{
		ISD:    addr.ISD(req.Isd),
		Base:   scrypto.Version(req.Base),
		Serial: scrypto.Version(req.Serial),
	}
	span := opentracing.SpanFromContext(ctx)
	logger := log.FromCtx(ctx)
	logger.Debug("Received TRC request", "id", trcID, "peer", peerAddr)

	if req.Isd > uint32(addr.MaxISD) {
		err := serrors.New("requested ISD not in range",
			"max", addr.MaxISD, "isd", req.Isd)
		logger.Debug("Invalid TRC request", "peer", peerAddr, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
		return nil, err
	}

	if !(trcID.Base.IsLatest() && trcID.Serial.IsLatest()) {
		if err := trcID.Validate(); err != nil {
			logger.Debug("Invalid TRC request", "peer", peerAddr, "err", err)
			s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
			return nil, err
		}
	} else if trcID.ISD == 0 {
		logger.Debug("Invalid TRC request", "peer", peerAddr, "err", cppki.ErrWildcardISD)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), cppki.ErrWildcardISD)
		return nil, cppki.ErrWildcardISD
	}
	trc, err := s.Provider.GetSignedTRC(ctx, trcID, trust.AllowInactive(), trust.Client(peerAddr))
	if err != nil {
		logger.Info("Unable to retrieve TRC", "id", trcID, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrInternal), err)
		return nil, err
	}
	return &endhost.GetTrcResponse{
		Trc: trc.Raw,
	}, nil
}

type requestLabels struct {
	Client  string
	ReqType string
	Result  string
}

func (l requestLabels) Expand() []string {
	return []string{
		"client", l.Client,
		"req_type", l.ReqType,
		prom.LabelResult, l.Result,
	}
}

func (l requestLabels) WithResult(result string) requestLabels {
	l.Result = result
	return l
}
