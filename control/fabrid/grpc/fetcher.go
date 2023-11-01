package grpc

import (
	"context"
	"errors"
	"github.com/scionproto/scion/pkg/addr"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	"github.com/scionproto/scion/pkg/snet"
	"time"
)

const (
	defaultRPCDialTimeout time.Duration = 2 * time.Second
)

var errNotReachable = serrors.New("remote not reachable")

type PolicyFetcher struct {
	Dialer     *libgrpc.QUICDialer
	Router     snet.Router
	MaxRetries int

	errorPaths map[snet.PathFingerprint]struct{}
}

func (f *PolicyFetcher) GetRemotePolicy(
	ctx context.Context,
	remoteIA addr.IA,
	req *experimental.RemotePolicyDescriptionRequest,
) (*experimental.PolicyDescriptionResponse, error) {
	var errList serrors.List
	f.errorPaths = make(map[snet.PathFingerprint]struct{})
	for i := 0; i < f.MaxRetries; i++ {
		rep, err := f.attemptFetchRemotePolicy(ctx, remoteIA, req)
		if errors.Is(err, errNotReachable) {
			return &experimental.PolicyDescriptionResponse{}, serrors.New(
				"remote policy fetch fetch failed",
				"try", i+1,
				"peer", remoteIA,
				"err", err,
			)
		}
		if err == nil {
			return rep, nil
		}
		errList = append(errList,
			serrors.WrapStr("fetching policy", err, "try", i+1, "peer", remoteIA),
		)
	}
	return &experimental.PolicyDescriptionResponse{}, serrors.WrapStr(
		"reached max retry attempts fetching remote policy",
		errList,
	)
}

func (f *PolicyFetcher) attemptFetchRemotePolicy(
	ctx context.Context,
	srcIA addr.IA,
	req *experimental.RemotePolicyDescriptionRequest,
) (*experimental.PolicyDescriptionResponse, error) {

	path, err := f.pathToDst(ctx, srcIA)
	if err != nil {
		return nil, err
	}
	remote := &snet.SVCAddr{
		IA:      srcIA,
		Path:    path.Dataplane(),
		NextHop: path.UnderlayNextHop(),
		SVC:     addr.SvcCS,
	}
	dialCtx, cancelF := context.WithTimeout(ctx, defaultRPCDialTimeout)
	defer cancelF()
	conn, err := f.Dialer.Dial(dialCtx, remote)
	if err != nil {
		return nil, serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := experimental.NewFABRIDInterServiceClient(conn)
	rep, err := client.GetLocalPolicyDescription(ctx,
		&experimental.PolicyDescriptionRequest{PolicyIdentifier: req.PolicyIdentifier})
	if err != nil {
		return nil, serrors.WrapStr("requesting level 1 key", err)
	}
	return rep, nil
}

func (f *PolicyFetcher) pathToDst(ctx context.Context, dst addr.IA) (snet.Path, error) {
	paths, err := f.Router.AllRoutes(ctx, dst)
	if err != nil {
		return nil, serrors.Wrap(errNotReachable, err)
	}
	if len(paths) == 0 {
		return nil, errNotReachable
	}
	for _, p := range paths {
		if _, ok := f.errorPaths[snet.Fingerprint(p)]; ok {
			continue
		}
		f.errorPaths[snet.Fingerprint(p)] = struct{}{}
		return p, nil
	}
	// we've tried out all the paths; we reset the map to retry them.
	f.errorPaths = make(map[snet.PathFingerprint]struct{})
	return paths[0], nil
}
