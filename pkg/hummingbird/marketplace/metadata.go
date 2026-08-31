// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package marketplace

import (
	"encoding/json"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/snet"
)

// ASesMetadata is a collection of several ASes' Hummingbird metadata in their PCBs.
type ASesMetadata struct {
	Marketplaces []NoteEntry `json:"hummingbird,omitempty"`
}

// NoteEntry is one marketplace that sells the reservations of the AS which advertised it.
// It holds only comparable fields, so that the same marketplace advertised by several ASes,
// or over several paths, can be counted with a map.
type NoteEntry struct {
	Name string `json:"name"`
	// APIProtocol is the protocol stack of APIAddress, for instance
	// "connectrpc/TLS/QUIC/SCION" for the SCION API, or "connectrpc/TLS/TCP".
	APIProtocol string `json:"api_protocol"`
	// APIAddress is where the API of the marketplace lives, viable by the protocol:
	// a SCION address for the SCION API, a URL for the TCP one.
	APIAddress                string `json:"api_address"`
	ClientRegistrationWebsite string `json:"client_registration_website"`
}

// ParseNote reads the Hummingbird part of one PCB note.
// A note unrelated to Hummingbird, or not JSON at all, is no marketplace metadata.
func ParseNote(note string) ASesMetadata {
	if note == "" {
		return ASesMetadata{}
	}
	var parsed ASesMetadata
	if err := json.Unmarshal([]byte(note), &parsed); err != nil {
		log.Debug("hummingbird: failed to parse a PCB note", "note", note, "err", err)
		return ASesMetadata{}
	}
	return parsed
}

// WithAPI returns the advertised marketplaces that carry an address to reach them at.
// An entry without one cannot be used, whatever else it says.
func (m ASesMetadata) WithAPI() []NoteEntry {
	reachable := make([]NoteEntry, 0, len(m.Marketplaces))
	for _, entry := range m.Marketplaces {
		if entry.APIAddress != "" {
			reachable = append(reachable, entry)
		}
	}
	return reachable
}

// MarketplacesFromPaths returns the marketplaces that the ASes of the given paths advertise,
// and counts how many notes advertised each one.
// The count lets a caller prefer a marketplace which is more used by the paths.
func MarketplacesFromPaths(paths []snet.Path) map[NoteEntry]int {
	found := map[NoteEntry]int{}
	for _, path := range paths {
		if path.Metadata() == nil {
			continue
		}
		for _, note := range path.Metadata().Notes {
			for _, entry := range ParseNote(note).WithAPI() {
				found[entry]++
			}
		}
	}
	return found
}
