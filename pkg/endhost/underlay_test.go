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
	"fmt"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/endhost"
	"github.com/stretchr/testify/assert"
)

func TestUnderlay(t *testing.T) {
	u := endhost.NewUnderlayService("http://[fd00:f00d:cafe::7f00:1c]:31022")
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
	defer cancelF()
	res, err := u.ListUnderlays(ctx, nil)
	assert.NoError(t, err)
	assert.NotNil(t, res.Udp)
	for _, router := range res.Udp.Routers {
		fmt.Println(router.Address, router.IsdAs, router.Interfaces)
	}
	t.Fail()
}
