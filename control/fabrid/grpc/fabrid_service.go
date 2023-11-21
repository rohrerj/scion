// Copyright 2023 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpc

import (
	"bytes"
	"context"
	"github.com/scionproto/scion/control/fabrid"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	fabridext "github.com/scionproto/scion/pkg/segment/extensions/fabrid"
	"time"
)

type Server struct {
	FabridManager *fabrid.FabridManager
	Fetcher       PolicyFetcher
}

func (s Server) GetMPLSMapIfNecessary(ctx context.Context, request *experimental.MPLSMapRequest) (*experimental.MPLSMapResponse, error) {
	if bytes.Equal(request.Hash, s.FabridManager.MPLSMap.CurrentHash) {
		return &experimental.MPLSMapResponse{Update: false}, nil
	}
	return &experimental.MPLSMapResponse{
		Update:       true,
		Hash:         s.FabridManager.MPLSMap.CurrentHash,
		MplsLabelMap: s.FabridManager.MPLSMap.Data,
	}, nil
}

func (s Server) GetRemotePolicyDescription(ctx context.Context, request *experimental.RemotePolicyDescriptionRequest) (*experimental.PolicyDescriptionResponse, error) {
	//TODO(jvanbommel): signature?
	identifier := fabrid.RemotePolicyIdentifier{ISDAS: request.IsdAs, Identifier: request.PolicyIdentifier}
	if val, ok := s.FabridManager.RemotePolicyCache[identifier]; ok && val.Expires.UnixNano() > time.Now().UnixNano() {
		return &experimental.PolicyDescriptionResponse{Description: val.Description}, nil
	}

	policy, err := s.Fetcher.GetRemotePolicy(ctx, addr.IA(request.IsdAs), request.PolicyIdentifier)
	if err != nil {
		return &experimental.PolicyDescriptionResponse{}, err
	}

	s.FabridManager.RemotePolicyCache[identifier] = fabrid.RemotePolicyDescription{Description: policy.Description, Expires: time.Now().Add(time.Hour * 3)}

	return &experimental.PolicyDescriptionResponse{Description: policy.Description}, nil
}

func (s Server) GetSupportedIndicesMap(_ context.Context, _ *experimental.SupportedIndicesRequest) (*experimental.SupportedIndicesResponse, error) {
	return &experimental.SupportedIndicesResponse{
		SupportedIndicesMap: fabridext.SupportedIndicesMapToPB(s.FabridManager.SupportedIndicesMap)}, nil
}

func (s Server) GetIndexIdentifierMap(_ context.Context, _ *experimental.IndexIdentifierMapRequest) (*experimental.IndexIdentifierMapResponse, error) {
	return &experimental.IndexIdentifierMapResponse{
		IndexIdentifierMap: fabridext.IndexIdentifierMapToPB(s.FabridManager.IndexIdentifierMap)}, nil
}

func (s Server) GetLocalPolicyDescription(_ context.Context, request *experimental.PolicyDescriptionRequest) (*experimental.PolicyDescriptionResponse, error) {
	if descr, ok := s.FabridManager.IdentifierDescriptionMap[request.PolicyIdentifier]; ok {
		return &experimental.PolicyDescriptionResponse{
			Description: descr}, nil
	}
	return &experimental.PolicyDescriptionResponse{}, errNotFound
}
