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

// ASNotes is the set of one AS marketplace notes, taken from the metadata in the PCB.
type ASNotes struct {
	Notes []NoteEntry `json:"hummingbird,omitempty"`
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
func ParseNote(note string) ASNotes {
	if note == "" {
		return ASNotes{}
	}
	var parsed ASNotes
	if err := json.Unmarshal([]byte(note), &parsed); err != nil {
		log.Debug("hummingbird: failed to parse a PCB note", "note", note, "err", err)
		return ASNotes{}
	}
	return parsed
}

// WithAPI returns the advertised marketplaces that carry an address to reach them at.
// An entry without one cannot be used, whatever else it says.
func (m ASNotes) WithAPI() []NoteEntry {
	reachable := make([]NoteEntry, 0, len(m.Notes))
	for _, entry := range m.Notes {
		if entry.APIAddress != "" {
			reachable = append(reachable, entry)
		}
	}
	return reachable
}

// UniqueAPIsOnly returns the advertised marketplaces with at most one entry per API address,
// keeping the first entry of every address in the order the AS advertised them.
// An AS commonly advertises the same marketplace once per protocol stack it speaks, and a
// client needs only one way of reaching it.
func (m ASNotes) UniqueAPIsOnly() ASNotes {
	seen := make(map[string]struct{}, len(m.Notes))
	unique := make([]NoteEntry, 0, len(m.Notes))
	for _, entry := range m.Notes {
		if _, ok := seen[entry.APIAddress]; ok {
			continue
		}
		seen[entry.APIAddress] = struct{}{}
		unique = append(unique, entry)
	}
	return ASNotes{Notes: unique}
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
