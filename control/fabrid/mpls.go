package fabrid

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

type MPLSMap struct {
	Data        map[uint32]uint32 // Even though the policy indices are only 8 bits, the backing data structure stores them as 32 bits so it can be reused in the protobuf message.
	CurrentHash []byte
}

//
//func (m *MPLSMap) Set(key uint8, value uint32) {
//	if v, ok := m.Data[uint32(key)]; ok && v == value {
//		return
//	}
//	m.Data[uint32(key)] = value
//	m.UpdateHash()
//}

func (m *MPLSMap) sortedKeys() []uint32 {
	// TODO(jvanbommel): Q At this point we should just use an orderedmap library
	orderedKeys := make([]uint32, 0, len(m.Data))
	for k := range m.Data {
		orderedKeys = append(orderedKeys, k)
	}
	sort.Slice(orderedKeys, func(i int, j int) bool {
		return orderedKeys[i] < orderedKeys[j]
	})
	return orderedKeys
}

// This method is to be called after all inserts and removes from the internal map
func (m *MPLSMap) UpdateHash() {
	h := sha256.New()
	for _, polIdx := range m.sortedKeys() {
		binary.Write(h, binary.BigEndian, polIdx)
		binary.Write(h, binary.BigEndian, m.Data[polIdx])
	}
	m.CurrentHash = h.Sum(nil)
}

//
//func (m *MPLSMap) GetHash() []byte {
//	return m.CurrentHash
//}
