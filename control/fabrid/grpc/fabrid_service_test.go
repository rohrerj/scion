package grpc

import (
	"context"
	"github.com/golang/mock/gomock"
	"github.com/scionproto/scion/control/fabrid"
	"github.com/scionproto/scion/control/fabrid/grpc/mock_grpc"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	fabrid_ext "github.com/scionproto/scion/pkg/segment/extensions/fabrid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestGetRemotePolicyDescription(t *testing.T) {
	ia := xtest.MustParseIA("1-ff00:00:100")

	tests := map[string]struct {
		LocalCache map[fabrid.RemotePolicyIdentifier]fabrid.RemotePolicyDescription

		PolicyIdentifier     uint32
		PolicyAtRemote       bool
		ExpectedFetcherCalls int
		ExpectedAssert       assert.ErrorAssertionFunc
		ExpectedResult       string
	}{
		"not present in cache": {
			LocalCache:           map[fabrid.RemotePolicyIdentifier]fabrid.RemotePolicyDescription{},
			PolicyIdentifier:     55,
			PolicyAtRemote:       true,
			ExpectedFetcherCalls: 1,
			ExpectedAssert:       assert.NoError,
			ExpectedResult:       "Test Policy",
		},
		"present in cache but expired": {
			LocalCache: map[fabrid.RemotePolicyIdentifier]fabrid.RemotePolicyDescription{
				fabrid.RemotePolicyIdentifier{
					ISDAS:      uint64(ia),
					Identifier: 56,
				}: {
					Description: "Test Policy Cached",
					Expires:     time.Now().Add(-5 * time.Hour),
				}},
			PolicyIdentifier:     56,
			PolicyAtRemote:       true,
			ExpectedFetcherCalls: 1,
			ExpectedAssert:       assert.NoError,
			ExpectedResult:       "Test Policy 2",
		},
		"present in cache and not expired": {
			LocalCache: map[fabrid.RemotePolicyIdentifier]fabrid.RemotePolicyDescription{
				fabrid.RemotePolicyIdentifier{
					ISDAS:      uint64(ia),
					Identifier: 57,
				}: {
					Description: "Test Policy Cached",
					Expires:     time.Now().Add(10 * time.Hour),
				}},
			PolicyIdentifier:     57,
			PolicyAtRemote:       true,
			ExpectedFetcherCalls: 0,
			ExpectedAssert:       assert.NoError,
			ExpectedResult:       "Test Policy Cached",
		},
		"not present at remote": {
			LocalCache:           map[fabrid.RemotePolicyIdentifier]fabrid.RemotePolicyDescription{},
			PolicyIdentifier:     58,
			PolicyAtRemote:       false,
			ExpectedFetcherCalls: 1,
			ExpectedAssert:       assert.Error,
			ExpectedResult:       "",
		},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fetcher := mock_grpc.NewMockPolicyFetcher(ctrl)
			fetcher.EXPECT().GetRemotePolicy(gomock.Any(), ia,
				tc.PolicyIdentifier).Times(tc.ExpectedFetcherCalls).DoAndReturn(
				func(ctx context.Context,
					remoteIA addr.IA,
					remotePolicyIdentifier uint32) (*experimental.PolicyDescriptionResponse,
					error) {
					if tc.PolicyAtRemote {
						return &experimental.PolicyDescriptionResponse{Description: tc.ExpectedResult}, nil
					}
					return &experimental.PolicyDescriptionResponse{}, serrors.New(
						"remote policy fetch fetch failed",
						"try", 1,
						"peer", remoteIA,
						"err", errNotFound,
					)
				})
			server := Server{
				FabridManager: &fabrid.FabridManager{
					RemotePolicyCache: tc.LocalCache,
				},
				Fetcher: fetcher,
			}
			descr, err := server.GetRemotePolicyDescription(context.Background(),
				&experimental.RemotePolicyDescriptionRequest{
					PolicyIdentifier: tc.PolicyIdentifier,
					IsdAs:            uint64(ia),
				})

			tc.ExpectedAssert(t, err)
			if tc.ExpectedResult != "" {
				require.Equal(t, tc.ExpectedResult, descr.Description)
			}
		})
	}
}

func TestGetSupportedIndicesMap(t *testing.T) {
	supportedIndices := fabrid_ext.SupportedIndicesMap{
		fabrid_ext.ConnectionPair{
			Ingress: fabrid_ext.ConnectionPoint{
				Type:   fabrid_ext.IPv4Range,
				IP:     "192.168.2.0",
				Prefix: 24,
			},
			Egress: fabrid_ext.ConnectionPoint{
				Type:        fabrid_ext.Interface,
				InterfaceId: 5,
			},
		}: []uint8{2, 8, 15}}

	server := Server{
		FabridManager: &fabrid.FabridManager{
			SupportedIndicesMap: supportedIndices,
		},
	}
	indices, err := server.GetSupportedIndicesMap(
		context.Background(),
		&experimental.SupportedIndicesRequest{},
	)
	require.NoError(t, err)
	require.Equal(t, supportedIndices,
		fabrid_ext.SupportedIndicesMapFromPB(indices.SupportedIndicesMap))
}

func TestGetIndexIdentifierMap(t *testing.T) {
	indexIdentifierMap := fabrid_ext.IndexIdentifierMap{
		2: &fabrid_ext.PolicyIdentifier{
			Type:       fabrid_ext.GlobalPolicy,
			Identifier: 22,
		},
		8: &fabrid_ext.PolicyIdentifier{
			Type:       fabrid_ext.LocalPolicy,
			Identifier: 1,
		},
		15: &fabrid_ext.PolicyIdentifier{
			Type:       fabrid_ext.GlobalPolicy,
			Identifier: 50,
		},
	}

	server := Server{
		FabridManager: &fabrid.FabridManager{
			IndexIdentifierMap: indexIdentifierMap,
		},
	}
	identifiers, err := server.GetIndexIdentifierMap(
		context.Background(),
		&experimental.IndexIdentifierMapRequest{},
	)
	require.NoError(t, err)
	require.Equal(t, indexIdentifierMap,
		fabrid_ext.IndexIdentifierMapFromPB(identifiers.IndexIdentifierMap))
}

func TestGetLocalPolicyDescription(t *testing.T) {
	tests := map[string]struct {
		Identifier               uint32
		IdentifierDescriptionMap map[uint32]string
		ExpectedDescription      string
		Assert                   assert.ErrorAssertionFunc
	}{
		"nonexistent local policy": {
			Identifier: 56,
			IdentifierDescriptionMap: map[uint32]string{
				56: "Test Policy",
			},
			ExpectedDescription: "Test Policy",
			Assert:              assert.NoError,
		},
		"existent local policy": {
			Identifier:               56,
			IdentifierDescriptionMap: map[uint32]string{},
			ExpectedDescription:      "",
			Assert:                   assert.Error,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			server := Server{
				FabridManager: &fabrid.FabridManager{
					IdentifierDescriptionMap: tc.IdentifierDescriptionMap,
				},
			}
			description, err := server.GetLocalPolicyDescription(context.Background(),
				&experimental.PolicyDescriptionRequest{
					PolicyIdentifier: tc.Identifier,
				})
			tc.Assert(t, err)
			if err == nil {
				require.Equal(t, tc.ExpectedDescription, description.Description)
			}
		})
	}
}

func TestGetMPLSMapIfNecessary(t *testing.T) {
	baseMPLSMap := fabrid.MPLSMap{
		Data:        map[uint32]uint32{1: 3001, 2: 2030, 3: 200, 255: 1999},
		CurrentHash: nil,
	}
	baseMPLSMap.UpdateHash()

	tests := map[string]struct {
		RequesterHash  []byte
		ExpectedUpdate bool
	}{
		"no hash": {
			RequesterHash:  nil,
			ExpectedUpdate: true,
		},
		"outdated hash": {
			RequesterHash: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
				0x30, 0x31, 0x32},
			ExpectedUpdate: true,
		},
		"up to date hash": {
			RequesterHash:  baseMPLSMap.CurrentHash,
			ExpectedUpdate: false,
		},
	}

	server := Server{
		FabridManager: &fabrid.FabridManager{
			MPLSMap: baseMPLSMap,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			resp, err := server.GetMPLSMapIfNecessary(context.Background(),
				&experimental.MPLSMapRequest{
					Hash: tc.RequesterHash,
				})
			require.NoError(t, err)
			require.Equal(t, tc.ExpectedUpdate, resp.Update)
			if resp.Update {
				require.Equal(t, server.FabridManager.MPLSMap.Data, resp.MplsLabelMap)
			}
		})
	}
}
