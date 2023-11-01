package fabrid

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	fabridpb "github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	"github.com/scionproto/scion/pkg/segment/extensions/digest"
	"net"
	"sort"
)

type SupportedIndicesMap map[ConnectionPair][]uint8

type IndexIdentifierMap map[uint8]*PolicyIdentifier

type PolicyType int32

const (
	LocalPolicy  PolicyType = 0
	GlobalPolicy PolicyType = 1
)

type Detached struct {
	SupportedIndicesMap SupportedIndicesMap
	IndexIdentiferMap   IndexIdentifierMap
}

type ConnectionPointType string

const (
	Unspecified ConnectionPointType = "unspecified"
	IPv4Range   ConnectionPointType = "ipv4"
	IPv6Range   ConnectionPointType = "ipv6"
	Interface   ConnectionPointType = "interface"
)

type ConnectionPoint struct {
	Type        ConnectionPointType
	IP          string // Stored as a string to allow it to be key of a map.
	Prefix      uint32
	InterfaceId uint16 // TODO(jvanbommel): this is actually not consistent in scion.
}

// To ensure that the connection point strings are identical, i.e. without padding, parse using the net library
func ConnectionPointFromString(IP string, Prefix uint32, Type ConnectionPointType) ConnectionPoint {
	var m net.IPMask
	if Type == IPv4Range {
		m = net.CIDRMask(int(Prefix), 8*net.IPv4len)
	} else if Type == IPv6Range {
		m = net.CIDRMask(int(Prefix), 8*net.IPv6len)
	}
	return ConnectionPoint{Type: Type, IP: net.ParseIP(IP).Mask(m).String(), Prefix: Prefix}
}

func (c *ConnectionPoint) IPNetwork() *net.IPNet {
	if c.Type == IPv4Range {
		m := net.CIDRMask(int(c.Prefix), 8*net.IPv4len)
		return &net.IPNet{IP: net.ParseIP(c.IP).Mask(m), Mask: m}
	} else if c.Type == IPv6Range {
		m := net.CIDRMask(int(c.Prefix), 8*net.IPv6len)
		return &net.IPNet{IP: net.ParseIP(c.IP).Mask(m), Mask: m}
	}
	return &net.IPNet{}
}

type ConnectionPair struct {
	Ingress ConnectionPoint
	Egress  ConnectionPoint
}

type PolicyIdentifier struct {
	Type       PolicyType
	Identifier uint32
}

func ConnectionPointToPB(point ConnectionPoint) *fabridpb.FABRIDConnectionPoint {
	switch point.Type {
	case IPv4Range:
		return &fabridpb.FABRIDConnectionPoint{
			Type:      fabridpb.FABRIDConnectionType_IPv4_RANGE,
			IpAddress: point.IPNetwork().IP,
			IpPrefix:  point.Prefix,
		}
	case IPv6Range:
		return &fabridpb.FABRIDConnectionPoint{
			Type:      fabridpb.FABRIDConnectionType_IPv6_RANGE,
			IpAddress: point.IPNetwork().IP,
			IpPrefix:  point.Prefix,
		}
	case Interface:
		return &fabridpb.FABRIDConnectionPoint{
			Type:      fabridpb.FABRIDConnectionType_INTERFACE,
			Interface: uint64(point.InterfaceId),
		}
	default:
		return &fabridpb.FABRIDConnectionPoint{}
	}
}

func ConnectionPointFromPB(point *fabridpb.FABRIDConnectionPoint) ConnectionPoint {
	switch point.Type {
	case fabridpb.FABRIDConnectionType_IPv4_RANGE:
		return ConnectionPoint{
			Type:   IPv4Range,
			IP:     net.IP(point.IpAddress).String(),
			Prefix: point.IpPrefix,
		}
	case fabridpb.FABRIDConnectionType_IPv6_RANGE:
		return ConnectionPoint{
			Type:   IPv6Range,
			IP:     net.IP(point.IpAddress).String(),
			Prefix: point.IpPrefix,
		}
	case fabridpb.FABRIDConnectionType_INTERFACE:
		return ConnectionPoint{
			Type:        Interface,
			InterfaceId: uint16(point.Interface),
		}
	default:
		return ConnectionPoint{}
	}
}

func SupportedIndicesMapToPB(indicesMap SupportedIndicesMap) []*fabridpb.FABRIDIndexMapEntry {
	supIndices := make([]*fabridpb.FABRIDIndexMapEntry, 0)
	for ie, indices := range indicesMap {
		indicesu32 := make([]uint32, len(indices))
		for i, index := range indices {
			indicesu32[i] = uint32(index)
		}
		supIndices = append(supIndices, &fabridpb.FABRIDIndexMapEntry{
			IePair: &fabridpb.FABRIDIngressEgressPair{
				Ingress: ConnectionPointToPB(ie.Ingress),
				Egress:  ConnectionPointToPB(ie.Egress),
			},
			SupportedPolicyIndices: indicesu32,
		})

	}
	return supIndices
}

func SupportedIndicesMapFromPB(indicesMap []*fabridpb.FABRIDIndexMapEntry) SupportedIndicesMap {
	supIndices := make(SupportedIndicesMap, 0)
	for _, entry := range indicesMap {
		indicesu8 := make([]uint8, len(entry.SupportedPolicyIndices))
		for i, index := range entry.SupportedPolicyIndices {
			indicesu8[i] = uint8(index)
		}
		supIndices[ConnectionPair{
			Ingress: ConnectionPointFromPB(entry.IePair.Ingress),
			Egress:  ConnectionPointFromPB(entry.IePair.Egress),
		}] = indicesu8

	}
	return supIndices
}

func IndexIdentifierMapToPB(identifierMap IndexIdentifierMap) map[uint32]*fabridpb.FABRIDPolicyIdentifier {
	identMap := make(map[uint32]*fabridpb.FABRIDPolicyIdentifier, len(identifierMap))
	for index, identifier := range identifierMap {
		if identifier.Type == GlobalPolicy {
			identMap[uint32(index)] = &fabridpb.FABRIDPolicyIdentifier{
				PolicyType:       fabridpb.FABRIDPolicyType_GLOBAL,
				PolicyIdentifier: identifier.Identifier,
			}
		} else if identifier.Type == LocalPolicy {

			identMap[uint32(index)] = &fabridpb.FABRIDPolicyIdentifier{
				PolicyType:       fabridpb.FABRIDPolicyType_LOCAL,
				PolicyIdentifier: identifier.Identifier,
			}
		}
	}
	return identMap
}

func IndexIdentifierMapFromPB(identifierMap map[uint32]*fabridpb.FABRIDPolicyIdentifier) IndexIdentifierMap {
	identMap := make(IndexIdentifierMap, len(identifierMap))
	for index, identifier := range identifierMap {
		if identifier.PolicyType == fabridpb.FABRIDPolicyType_GLOBAL {
			identMap[uint8(index)] = &PolicyIdentifier{
				Type:       GlobalPolicy,
				Identifier: identifier.PolicyIdentifier,
			}
		} else if identifier.PolicyType == fabridpb.FABRIDPolicyType_LOCAL {
			identMap[uint8(index)] = &PolicyIdentifier{
				Type:       LocalPolicy,
				Identifier: identifier.PolicyIdentifier,
			}
		}
	}
	return identMap
}

func DetachedToPB(detached *Detached) *fabridpb.FABRIDDetachedExtension {
	return &fabridpb.FABRIDDetachedExtension{
		Maps: &fabridpb.FABRIDDetachableMaps{
			SupportedIndicesMap: SupportedIndicesMapToPB(detached.SupportedIndicesMap),
			IndexIdentifierMap:  IndexIdentifierMapToPB(detached.IndexIdentiferMap),
		},
	}
}

func DetachedFromPB(detached *fabridpb.FABRIDDetachedExtension) *Detached {
	//todo(jvanbommel): nil check
	return &Detached{
		SupportedIndicesMap: SupportedIndicesMapFromPB(detached.Maps.SupportedIndicesMap),
		IndexIdentiferMap:   IndexIdentifierMapFromPB(detached.Maps.IndexIdentifierMap),
	}
}

func (d *Detached) String() string {
	base := " indexIdentifierMap: ["
	orderedKeys := make([]uint8, 0, len(d.IndexIdentiferMap))
	for k, _ := range d.IndexIdentiferMap {
		orderedKeys = append(orderedKeys, k)
	}
	sort.Slice(orderedKeys, func(i int, j int) bool {
		return orderedKeys[i] < orderedKeys[j]
	}) //TODO (jvanbommel): do this sorting into an ordered map directly at load ?
	for _, k := range orderedKeys {
		base += fmt.Sprintf("{ index: %d, type: %d, identifier: %d }", k, d.IndexIdentiferMap[k].Type, d.IndexIdentiferMap[k].Identifier)
	}
	base += "], supportedIndicesMap: ["

	orderedKeysSupIndex := make([]ConnectionPair, 0, len(d.SupportedIndicesMap))
	for k, _ := range d.SupportedIndicesMap {
		orderedKeysSupIndex = append(orderedKeysSupIndex, k)
	}
	sort.Slice(orderedKeysSupIndex, func(i int, j int) bool {
		return orderedKeysSupIndex[i].Ingress.Type < orderedKeysSupIndex[j].Ingress.Type ||
			orderedKeysSupIndex[i].Ingress.IP < orderedKeysSupIndex[j].Ingress.IP ||
			orderedKeysSupIndex[i].Ingress.Prefix < orderedKeysSupIndex[j].Ingress.Prefix ||
			orderedKeysSupIndex[i].Ingress.InterfaceId < orderedKeysSupIndex[j].Ingress.InterfaceId ||
			orderedKeysSupIndex[i].Egress.Type < orderedKeysSupIndex[j].Egress.Type ||
			orderedKeysSupIndex[i].Egress.IP < orderedKeysSupIndex[j].Egress.IP ||
			orderedKeysSupIndex[i].Egress.Prefix < orderedKeysSupIndex[j].Egress.Prefix ||
			orderedKeysSupIndex[i].Egress.InterfaceId < orderedKeysSupIndex[j].Egress.InterfaceId
	}) //TODO(jvanbommel): ensure this is stable sorting
	for _, k := range orderedKeysSupIndex {
		base += fmt.Sprintf("{ ingress: { type: %s ", k.Ingress.Type)
		if k.Ingress.Type == Interface {
			base += fmt.Sprintf("interfaceId: %d }", k.Ingress.InterfaceId)
		} else if k.Ingress.Type == IPv4Range || k.Ingress.Type == IPv6Range {
			base += fmt.Sprintf("ip: %s, prefix: %d }", k.Ingress.IP, k.Ingress.Prefix)
		}

		base += fmt.Sprintf("} egress : { type: %s ", k.Egress.Type)
		if k.Egress.Type == Interface {
			base += fmt.Sprintf("interfaceId: %d } ", k.Egress.InterfaceId)
		} else if k.Egress.Type == IPv4Range || k.Egress.Type == IPv6Range {
			base += fmt.Sprintf("ip: %s, prefix: %d } ", k.Egress.IP, k.Egress.Prefix)
		}
		base += " supports: ["
		supported := d.SupportedIndicesMap[k]
		sort.Slice(supported, func(i int, j int) bool {
			return supported[i] < supported[j]
		})
		for _, z := range supported {
			base += fmt.Sprintf("%d, ", z)
		}
		base += "] } "
	}
	return base
}
func (d *Detached) Hash() []byte {
	h := sha256.New()
	orderedKeys := make([]uint8, 0, len(d.IndexIdentiferMap))
	for k, _ := range d.IndexIdentiferMap {
		orderedKeys = append(orderedKeys, k)
	}
	sort.Slice(orderedKeys, func(i int, j int) bool {
		return orderedKeys[i] < orderedKeys[j]
	})
	for _, k := range orderedKeys {
		binary.Write(h, binary.BigEndian, k)
		binary.Write(h, binary.BigEndian, d.IndexIdentiferMap[k].Type)
		binary.Write(h, binary.BigEndian, d.IndexIdentiferMap[k].Identifier)
	}
	orderedKeysSupIndex := make([]ConnectionPair, 0, len(d.SupportedIndicesMap))
	for k, _ := range d.SupportedIndicesMap {
		orderedKeysSupIndex = append(orderedKeysSupIndex, k)
	}
	sort.Slice(orderedKeysSupIndex, func(i int, j int) bool {
		return orderedKeysSupIndex[i].Ingress.Type < orderedKeysSupIndex[j].Ingress.Type ||
			orderedKeysSupIndex[i].Ingress.IP < orderedKeysSupIndex[j].Ingress.IP ||
			orderedKeysSupIndex[i].Ingress.Prefix < orderedKeysSupIndex[j].Ingress.Prefix ||
			orderedKeysSupIndex[i].Ingress.InterfaceId < orderedKeysSupIndex[j].Ingress.InterfaceId ||
			orderedKeysSupIndex[i].Egress.Type < orderedKeysSupIndex[j].Egress.Type ||
			orderedKeysSupIndex[i].Egress.IP < orderedKeysSupIndex[j].Egress.IP ||
			orderedKeysSupIndex[i].Egress.Prefix < orderedKeysSupIndex[j].Egress.Prefix ||
			orderedKeysSupIndex[i].Egress.InterfaceId < orderedKeysSupIndex[j].Egress.InterfaceId
	})
	for _, k := range orderedKeysSupIndex {
		binary.Write(h, binary.BigEndian, k.Ingress.Type)
		if k.Ingress.Type == Interface {
			binary.Write(h, binary.BigEndian, k.Ingress.InterfaceId)
		} else if k.Ingress.Type == IPv4Range || k.Ingress.Type == IPv6Range {
			binary.Write(h, binary.BigEndian, k.Ingress.Prefix)
			binary.Write(h, binary.BigEndian, k.Ingress.IP)
		}

		binary.Write(h, binary.BigEndian, k.Egress.Type)
		if k.Egress.Type == Interface {
			binary.Write(h, binary.BigEndian, k.Egress.InterfaceId)
		} else if k.Egress.Type == IPv4Range || k.Egress.Type == IPv6Range {
			binary.Write(h, binary.BigEndian, k.Egress.Prefix)
			binary.Write(h, binary.BigEndian, k.Egress.IP)
		}
		supported := d.SupportedIndicesMap[k]
		sort.Slice(supported, func(i int, j int) bool {
			return supported[i] < supported[j]
		})
		binary.Write(h, binary.BigEndian, supported)
	}
	return h.Sum(nil)[0:digest.DigestLength]
}
