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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scionEntry is the note of the marketplace address block of the Hummingbird APIs
// document, with the keys the specification gives.
const scionEntry = `{
	"hummingbird": [
		{
			"name": "SCIONCreditCardMarketplace",
			"api_protocol": "connectrpc/TLS/QUIC/SCION",
			"api_address": "[1-ff00:0:110,192.0.2.1]:80",
			"client_registration_website": "https://www.netsec-ethz.org"
		}
	]
}`

// TestParseNote covers the note shapes an AS can put on a path,
// including the ones unrelated to Hummingbird.
func TestParseNote(t *testing.T) {
	testCases := map[string]struct {
		note      string
		reachable int
	}{
		"a marketplace over SCION":    {note: scionEntry, reachable: 1},
		"an entry without an address": {note: `{"hummingbird":[{"name":"x"}]}`, reachable: 0},
		"an empty list":               {note: `{"hummingbird":[]}`, reachable: 0},
		"a note about something else": {note: `{"latency":{"inter":100}}`, reachable: 0},
		"the superseded capability":   {note: `{"hummingbird-v0":{"supported":true}}`, reachable: 0},
		"an empty note":               {note: "", reachable: 0},
		"a note that is not JSON":     {note: "not json", reachable: 0},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Len(t, ParseNote(tc.note).WithAPI(), tc.reachable)
		})
	}
}

// TestParseNoteFields checks that every key of the specification is read,
// since a wrong tag would silently leave a field empty rather than fail.
func TestParseNoteFields(t *testing.T) {
	reachable := ParseNote(scionEntry).WithAPI()
	require.Len(t, reachable, 1)
	assert.Equal(t, NoteEntry{
		Name:                      "SCIONCreditCardMarketplace",
		APIProtocol:               "connectrpc/TLS/QUIC/SCION",
		APIAddress:                "[1-ff00:0:110,192.0.2.1]:80",
		ClientRegistrationWebsite: "https://www.netsec-ethz.org",
	}, reachable[0])
}

// TestNoteEntryIsComparable pins that NoteEntry can key a map,
// which is what MarketplacesFromPaths relies on to count how often a marketplace was advertised.
func TestNoteEntryIsComparable(t *testing.T) {
	counted := map[NoteEntry]int{}
	entry := ParseNote(scionEntry).WithAPI()[0]
	counted[entry]++
	counted[entry]++
	assert.Equal(t, 2, counted[entry])
}
