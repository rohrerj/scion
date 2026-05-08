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

package snap_test

import (
	"context"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/snap"
)

func TestSnap(t *testing.T) {
	snapControlURL := "http://s01.chgtg1.snap.anapaya.net:5001"
	token := "REDACTED"
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
	defer cancelF()
	snap.Init(ctx, snapControlURL, token)
	t.Fail()
}
