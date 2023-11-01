package grpc

import (
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

func (s Server) GetRemotePolicyDescription(ctx context.Context, request *experimental.RemotePolicyDescriptionRequest) (*experimental.PolicyDescriptionResponse, error) {
	//TODO(jvanbommel): signature?
	identifier := fabrid.RemotePolicyIdentifier{ISDAS: request.IsdAs, Identifier: request.PolicyIdentifier}
	if val, ok := s.FabridManager.RemotePolicyCache[identifier]; ok && val.Expires.UnixNano() > time.Now().UnixNano() {
		return &experimental.PolicyDescriptionResponse{Description: val.Description}, nil
	}

	policy, err := s.Fetcher.GetRemotePolicy(ctx, addr.IA(request.IsdAs), request)
	if err != nil {
		return &experimental.PolicyDescriptionResponse{}, nil
	}

	s.FabridManager.RemotePolicyCache[identifier] = fabrid.RemotePolicyDescription{Description: policy.Description, Expires: time.Now().Add(time.Hour * 3)}

	return &experimental.PolicyDescriptionResponse{Description: policy.Description}, nil
}

func (s Server) GetSupportedIndicesMap(ctx context.Context, request *experimental.SupportedIndicesRequest) (*experimental.SupportedIndicesResponse, error) {
	return &experimental.SupportedIndicesResponse{
		SupportedIndicesMap: fabridext.SupportedIndicesMapToPB(s.FabridManager.SupportedIndicesMap)}, nil
}

func (s Server) GetIndexIdentifierMap(ctx context.Context, request *experimental.IndexIdentifierMapRequest) (*experimental.IndexIdentifierMapResponse, error) {
	return &experimental.IndexIdentifierMapResponse{
		IndexIdentifierMap: fabridext.IndexIdentifierMapToPB(s.FabridManager.IndexIdentifierMap)}, nil
}

func (s Server) GetLocalPolicyDescription(ctx context.Context, request *experimental.PolicyDescriptionRequest) (*experimental.PolicyDescriptionResponse, error) {
	return &experimental.PolicyDescriptionResponse{
		Description: s.FabridManager.IdentifierDescriptionMap[request.PolicyIdentifier]}, nil
}
