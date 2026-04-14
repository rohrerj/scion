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
	"testing"
)

func TestPath(t *testing.T) {
	/*p := endhost.NewPathService("http://[fd00:f00d:cafe::7f00:1c]:31022")
	p.PageSize = 64
	p.PageToken = "0"
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*5)
	defer cancelF()
	src, err := addr.ParseIA("1-ff00:0:111")
	assert.NoError(t, err)
	dst, err := addr.ParseIA("2-ff00:0:211")
	assert.NoError(t, err)
	up, core, down, err := p.Segments(ctx, dst, src)
	paths := combinator.Combine(src, dst, up, core, down, false)
	for _, path := range paths {
		fmt.Println(path.Metadata.Interfaces)
	}
	fmt.Println("up segments")
	for _, upSegment := range up {
		for _, asEntry := range upSegment.ASEntries {
			fmt.Print(asEntry.Local, asEntry.HopEntry.HopField.ConsIngress, asEntry.HopEntry.HopField.ConsEgress, ", ")
		}
		fmt.Println()
	}
	fmt.Println("core segments")
	for _, coreSegment := range core {
		for _, asEntry := range coreSegment.ASEntries {
			fmt.Print(asEntry.Local, asEntry.HopEntry.HopField.ConsIngress, asEntry.HopEntry.HopField.ConsEgress, ", ")
		}
		fmt.Println()
	}
	fmt.Println("down segments")
	for _, downSegment := range down {
		for _, asEntry := range downSegment.ASEntries {
			fmt.Print(asEntry.Local, asEntry.HopEntry.HopField.ConsIngress, asEntry.HopEntry.HopField.ConsEgress, ", ")
		}
		fmt.Println()
	}
	assert.NoError(t, err)
	fmt.Println(len(up), len(core), len(down), len(paths))
	t.Fail()*/
}
