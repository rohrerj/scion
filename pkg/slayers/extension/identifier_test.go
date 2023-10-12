// Copyright 2023 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package extension_test

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/stretchr/testify/assert"
)

func TestIdentifierDecode(t *testing.T) {
	type test struct {
		name          string
		o             *slayers.EndToEndOption
		baseTimestamp uint32
		validate      func(extension.IdentifierOption, error, *testing.T)
	}
	unixNow := uint32(time.Now().Unix())
	tests := []test{
		{
			name: "wrong option type",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabrid,
				OptData: []byte{
					0x0, 0x0, 0x0, 0x0,
					0x0, 0x0, 0x0, 0x0,
				},
			},
			baseTimestamp: unixNow,
			validate: func(id extension.IdentifierOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "raw data too short",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeIdentifier,
				OptData: []byte{
					0x0, 0x0, 0x0, 0x0,
					0x0, 0x0, 0x0,
				},
			},
			baseTimestamp: unixNow,
			validate: func(id extension.IdentifierOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "correct timestamp",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeIdentifier,
				OptData: []byte{
					0xff, 0x00, 0x00, 0x01,
					0x01, 0x02, 0x03, 0x04,
				},
			},
			baseTimestamp: unixNow,
			validate: func(id extension.IdentifierOption, err error, t *testing.T) {
				assert.NoError(t, err)
				expectedTime := int64(unixNow)*1000 + 0x7000001
				assert.Equal(t, expectedTime, id.Timestamp.UnixMilli())
				assert.Equal(t, uint32(0x01020304), id.PacketID)
			},
		},
	}
	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				id, err := extension.ParseIdentifierOption(tc.o, tc.baseTimestamp)
				tc.validate(id, err, t)
			})
		}(tc)
	}
}
