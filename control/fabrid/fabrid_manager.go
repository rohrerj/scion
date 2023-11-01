package fabrid

import (
	"github.com/scionproto/scion/control/config"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/extensions/fabrid"
	"gopkg.in/yaml.v2"
	"os"
	"time"
)

const MaxFabridPolicies = 255

type RemotePolicyIdentifier struct {
	ISDAS      uint64
	Identifier uint32
}

type RemotePolicyDescription struct {
	Description string
	Expires     time.Time
}

type FabridManager struct {
	Config                   *config.FABRIDConfig
	SupportedIndicesMap      fabrid.SupportedIndicesMap
	IndexIdentifierMap       fabrid.IndexIdentifierMap
	IdentifierDescriptionMap map[uint32]string
	RemotePolicyCache        map[RemotePolicyIdentifier]RemotePolicyDescription
}

func NewFabridManager(configPath string) (*FabridManager, error) {
	// TODO(jvanbommel): Read all policies from directory.
	b, err := os.ReadFile(configPath)
	if err != nil {
		return nil, serrors.WrapStr("Unable to read the fabrid policies in file", err, "path", configPath)
	}
	fabridYaml, err := parseFABRIDYaml(b)
	if err != nil {
		return nil, err
	}

	log.Debug("Loaded FABRID config", "cfg", fabridYaml)
	if len(fabridYaml.Policies) > MaxFabridPolicies {
		return nil, serrors.New("Amount of FABRID policies exceeds limit.")
	}

	indexIdentifierMap := make(map[uint8]*fabrid.PolicyIdentifier, len(fabridYaml.Policies))
	supportedIndicesMap := make(map[fabrid.ConnectionPair][]uint8)
	identifierDescriptionMap := make(map[uint32]string)

	for i, policy := range fabridYaml.Policies {
		if policy.IsLocalPolicy {
			indexIdentifierMap[uint8(i)] = &fabrid.PolicyIdentifier{
				Type:       fabrid.LocalPolicy,
				Identifier: policy.LocalIdentifier,
			}
			identifierDescriptionMap[policy.LocalIdentifier] = policy.LocalDescription
		} else {
			indexIdentifierMap[uint8(i)] = &fabrid.PolicyIdentifier{
				Type:       fabrid.GlobalPolicy,
				Identifier: policy.GlobalIdentifier,
			}
		}
		for _, connection := range policy.SupportedBy {
			ie := fabrid.ConnectionPair{
				Ingress: fabrid.ConnectionPointFromString(connection.Ingress.IPAddress, uint32(connection.Ingress.Prefix), connection.Ingress.Type),
				Egress:  fabrid.ConnectionPointFromString(connection.Egress.IPAddress, uint32(connection.Egress.Prefix), connection.Egress.Type),
			}
			supportedIndicesMap[ie] = append(supportedIndicesMap[ie], uint8(i))
		}

	}

	return &FabridManager{Config: fabridYaml, IndexIdentifierMap: indexIdentifierMap, SupportedIndicesMap: supportedIndicesMap}, nil
}

func (f *FabridManager) Active() bool {
	return len(f.SupportedIndicesMap) > 0
}

// TODO(jvanbommel): change assign autoincrement ints

func parseFABRIDYaml(b []byte) (*config.FABRIDConfig, error) {
	p := &config.FABRIDConfig{}
	if err := yaml.UnmarshalStrict(b, p); err != nil {
		return nil, serrors.WrapStr("Unable to parse policy", err)
	}
	return p, nil
}
