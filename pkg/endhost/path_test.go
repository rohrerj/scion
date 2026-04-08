// Copyright 2026 ETH Zurich
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

package endhost_test

import (
	"context"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/endhost"
	"github.com/stretchr/testify/assert"
)

func TestPath(t *testing.T) {
	p := endhost.NewPathService("http://[fd00:f00d:cafe::7f00:1c]:31022")
	p.PageSize = 16
	p.PageToken = "0"
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
	defer cancelF()
	src, err := addr.ParseIA("1-ff00:0:111")
	assert.NoError(t, err)
	dst, err := addr.ParseIA("2-ff00:0:222")
	assert.NoError(t, err)
	_, err = p.Paths(ctx, dst, src)
	assert.NoError(t, err)
	p.PageToken = "1"
	_, err = p.Paths(ctx, dst, src)
	assert.NoError(t, err)
	t.Fail()
}
