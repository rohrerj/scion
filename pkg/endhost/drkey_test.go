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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/endhost"
	"github.com/stretchr/testify/assert"
)

func TestDRKey(t *testing.T) {
	src := "fd00:f00d:cafe::7f00:1d"
	//dst := "fd00:f00d:cafe::7f00:3b"
	service := endhost.NewDRKeyService("http://[fd00:f00d:cafe::7f00:1c]:31022", src)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
	defer cancelF()
	srcIA, err := addr.ParseIA("1-ff00:0:111")
	assert.NoError(t, err)
	dstIA, err := addr.ParseIA("2-ff00:0:211")
	assert.NoError(t, err)

	meta := drkey.ASHostMeta{
		Validity: time.Now().Add(time.Minute),
		ProtoId:  drkey.SCMP,
		SrcIA:    dstIA,
		DstIA:    srcIA,
		DstHost:  src,
	}
	key, err := service.ASHostKey(ctx, meta)
	assert.NoError(t, err)
	fmt.Println("begin key")
	fmt.Println(key)
	fmt.Println("end key")
	t.Fail()
}
