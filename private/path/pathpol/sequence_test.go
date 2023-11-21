// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package pathpol

import (
	"encoding/json"
	"fmt"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
)

func TestNewSequence(t *testing.T) {
	tests := map[string]assert.ErrorAssertionFunc{
		"0-0-0#0": assert.Error,
		"0#0#0":   assert.Error,
		"0":       assert.NoError,
		"1#0":     assert.Error,
		"1-0":     assert.NoError,
	}
	for seq, assertion := range tests {
		t.Run(seq, func(t *testing.T) {
			_, err := NewSequence(seq)
			assertion(t, err, seq)
		})
	}
}

func TestSequenceEval(t *testing.T) {
	tests := map[string]struct {
		Seq        *Sequence
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		"Empty path": {
			Seq:        newSequence(t, "0-0#0"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 0,
		},
		"Asterisk matches empty path": {
			Seq:        newSequence(t, "0*"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 1,
		},
		"Asterisk on non-wildcard matches empty path": {
			Seq:        newSequence(t, "1-ff00:0:110#1,2*"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 1,
		},
		"Double Asterisk matches empty path": {
			Seq:        newSequence(t, "0* 0*"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 1,
		},
		"QuestionMark matches empty path": {
			Seq:        newSequence(t, "0*"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 1,
		},
		"Asterisk and QuestionMark matches empty path": {
			Seq:        newSequence(t, "0* 0?"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 1,
		},
		"Plus does not match empty path": {
			Seq:        newSequence(t, "0+"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 0,
		},
		"Length not matching": {
			Seq:        newSequence(t, "0-0#0"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		"Two Wildcard matching": {
			Seq:        newSequence(t, "0-0#0 0-0#0"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Longer Wildcard matching": {
			Seq:        newSequence(t, "0-0#0 0-0#0 0-0#0 0-0#0"),
			Src:        xtest.MustParseIA("1-ff00:0:122"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 2,
		},
		"Two Explicit matching": {
			Seq:        newSequence(t, "1-ff00:0:133#1019 1-ff00:0:132#1910"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:132"),
			ExpPathNum: 1,
		},
		"AS double IF matching": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1910,1916 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"AS IF matching, first wildcard": {
			Seq:        newSequence(t, "0 1-ff00:0:132#0,1916 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching": {
			Seq: newSequence(t, "1-ff00:0:122#1815 1-ff00:0:121#1518,1530 "+
				"1-ff00:0:120#3015,3122 2-ff00:0:220#2231,2224 2-ff00:0:221#2422"),
			Src:        xtest.MustParseIA("1-ff00:0:122"),
			Dst:        xtest.MustParseIA("2-ff00:0:221"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching, single wildcard": {
			Seq: newSequence(t, "1-ff00:0:133#1018 1-ff00:0:122#1810,1815 "+
				"1-ff00:0:121#0,1530 1-ff00:0:120#3015,2911 1-ff00:0:110#1129"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching, reverse single wildcard": {
			Seq: newSequence(t, "1-ff00:0:133#1018 1-ff00:0:122#1810,1815 "+
				"1-ff00:0:121#1530,0 1-ff00:0:120#3015,2911 1-ff00:0:110#1129"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 0,
		},
		"Longer Explicit matching, multiple wildcard": {
			Seq: newSequence(t, "1-ff00:0:133#1018 1-ff00:0:122#0,1815 "+
				"1-ff00:0:121#0,1530 1-ff00:0:120#3015,0 1-ff00:0:110#1129"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching, mixed wildcard types": {
			Seq: newSequence(t, "1-ff00:0:133#0 1 "+
				"0-0#0 1-ff00:0:120#0 1-ff00:0:110#1129"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching, mixed wildcard types, two paths": {
			Seq: newSequence(t, "1-ff00:0:133#0 1-0#0 "+
				"0-0#0 1-0#0 1-ff00:0:110#0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 2,
		},
		"Nil sequence does not filter": {
			Seq:        nil,
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Asterisk matches multiple hops": {
			Seq:        newSequence(t, "0*"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Asterisk matches zero hops": {
			Seq:        newSequence(t, "0 0 0*"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Plus matches multiple hops": {
			Seq:        newSequence(t, "0+"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Plus doesn't match zero hops": {
			Seq:        newSequence(t, "0 0 0+"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		"Question mark matches zero hops": {
			Seq:        newSequence(t, "0 0 0?"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Question mark matches one hop": {
			Seq:        newSequence(t, "0 0?"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Question mark doesn't match two hops": {
			Seq:        newSequence(t, "0?"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		"Successful match on hop count": {
			Seq:        newSequence(t, "0 0 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		"Failed match on hop count": {
			Seq:        newSequence(t, "0 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
		"Select one of the intermediate ASes": {
			Seq:        newSequence(t, "0 2-ff00:0:221 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		"Select two alternative intermediate ASes": {
			Seq:        newSequence(t, "0 (2-ff00:0:221 | 2-ff00:0:210) 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		"Alternative intermediate ASes, but one doesn't exist": {
			Seq:        newSequence(t, "0 (2-ff00:0:221 |64-12345) 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		"Or has higher priority than concatenation": {
			Seq:        newSequence(t, "0 2-ff00:0:221|64-12345 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		"Question mark has higher priority than concatenation": {
			Seq:        newSequence(t, "0 0 0 ?  "),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		"Parentheses change priority": {
			Seq:        newSequence(t, "(0 0)?"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
		"Single interface matches inbound interface": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1910 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Single interface matches outbound interface": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1916 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Single non-matching interface": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1917 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 0,
		},
		"Left interface matches inbound": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1910,0 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Left interface doesn't match outbound": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1916,0 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 0,
		},
		"Right interface matches outbound": {
			Seq:        newSequence(t, "0 1-ff00:0:132#0,1916 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Right interface doesn't match inbound": {
			Seq:        newSequence(t, "0 1-ff00:0:132#0,1910 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 0,
		},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			paths := pp.GetPaths(test.Src, test.Dst)
			if test.Seq != nil {
				fmt.Printf("\tName: %s, RE: %s\n\n", name, test.Seq.restr)
			}
			outPaths := test.Seq.Eval(paths)
			assert.Equal(t, test.ExpPathNum, len(outPaths))
		})
	}
}

func TestSequenceEvalPolicies(t *testing.T) {
	tests := map[string]struct {
		Seq      *Sequence
		Path     snetpath.Path
		Expected int
	}{
		"Wildcard path with policy": {
			Seq: newSequence(t, "(0-0#0@(G44) | 0)*"),
			Path: snetpath.Path{
				Src: xtest.MustParseIA("2-ff00:0:212"),
				Dst: xtest.MustParseIA("2-ff00:0:222"),
				Meta: snet.PathMetadata{
					Interfaces: []snet.PathInterface{
						{
							IA: xtest.MustParseIA("2-ff00:0:212"),
							ID: common.IFIDType(3),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:214"),
							ID: common.IFIDType(5),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:216"),
							ID: common.IFIDType(6),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:222"),
							ID: common.IFIDType(7),
						},
					},
					FabridPolicies: [][]*snet.FabridPolicyIdentifier{
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 66,
								Type:       snet.FabridGlobalPolicy,
							},
						},
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 1111,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 1111,
								Type:       snet.FabridGlobalPolicy,
							},
						},
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 22,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 11,
								Type:       snet.FabridGlobalPolicy,
							},
						},
					},
				},
			},
			Expected: 1,
		},
		"Only two policies allowed": {
			Seq: newSequence(t, "(0@((G44|G66)))*"),
			Path: snetpath.Path{
				Src: xtest.MustParseIA("2-ff00:0:212"),
				Dst: xtest.MustParseIA("2-ff00:0:222"),
				Meta: snet.PathMetadata{
					Interfaces: []snet.PathInterface{
						{
							IA: xtest.MustParseIA("2-ff00:0:212"),
							ID: common.IFIDType(3),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:214"),
							ID: common.IFIDType(5),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:216"),
							ID: common.IFIDType(6),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:222"),
							ID: common.IFIDType(7),
						},
					},
					FabridPolicies: [][]*snet.FabridPolicyIdentifier{
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 66,
								Type:       snet.FabridGlobalPolicy,
							},
						},
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
						},
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 66,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 11,
								Type:       snet.FabridGlobalPolicy,
							},
						},
					},
				},
			},
			Expected: 1,
		},
		"Only two policy allowed, none exist": {
			Seq: newSequence(t, "(0@((G44|G66)))*"),
			Path: snetpath.Path{
				Src: xtest.MustParseIA("2-ff00:0:212"),
				Dst: xtest.MustParseIA("2-ff00:0:222"),
				Meta: snet.PathMetadata{
					Interfaces: []snet.PathInterface{
						{
							IA: xtest.MustParseIA("2-ff00:0:212"),
							ID: common.IFIDType(3),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:214"),
							ID: common.IFIDType(5),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:216"),
							ID: common.IFIDType(6),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:222"),
							ID: common.IFIDType(7),
						},
					},
					FabridPolicies: [][]*snet.FabridPolicyIdentifier{
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 66,
								Type:       snet.FabridGlobalPolicy,
							},
						},
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
						},
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 22,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 11,
								Type:       snet.FabridGlobalPolicy,
							},
						},
					},
				},
			},
			Expected: 0,
		},
		"Both policies required": {
			Seq: newSequence(t, "(0@((G44,G66)))*"),
			Path: snetpath.Path{
				Src: xtest.MustParseIA("2-ff00:0:212"),
				Dst: xtest.MustParseIA("2-ff00:0:222"),
				Meta: snet.PathMetadata{
					Interfaces: []snet.PathInterface{
						{
							IA: xtest.MustParseIA("2-ff00:0:212"),
							ID: common.IFIDType(3),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:214"),
							ID: common.IFIDType(5),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:216"),
							ID: common.IFIDType(6),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:222"),
							ID: common.IFIDType(7),
						},
					},
					FabridPolicies: [][]*snet.FabridPolicyIdentifier{
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 66,
								Type:       snet.FabridGlobalPolicy,
							},
						},
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 66,
								Type:       snet.FabridGlobalPolicy,
							},
						},
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 66,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 22,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
						},
					},
				},
			},
			Expected: 1,
		},
		"Both policies required, none exist": {
			Seq: newSequence(t, "(0@((G44,G66)))*"),
			Path: snetpath.Path{
				Src: xtest.MustParseIA("2-ff00:0:212"),
				Dst: xtest.MustParseIA("2-ff00:0:222"),
				Meta: snet.PathMetadata{
					Interfaces: []snet.PathInterface{
						{
							IA: xtest.MustParseIA("2-ff00:0:212"),
							ID: common.IFIDType(3),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:214"),
							ID: common.IFIDType(5),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:216"),
							ID: common.IFIDType(6),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:222"),
							ID: common.IFIDType(7),
						},
					},
					FabridPolicies: [][]*snet.FabridPolicyIdentifier{
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 66,
								Type:       snet.FabridGlobalPolicy,
							},
						},
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 11,
								Type:       snet.FabridGlobalPolicy,
							},
						},
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 66,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 22,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
						},
					},
				},
			},
			Expected: 0,
		},
		"Specific policy at specific hop": {
			Seq: newSequence(t, "(0* 2-ff00:0:214@L22+ 0*)"),
			Path: snetpath.Path{
				Src: xtest.MustParseIA("2-ff00:0:212"),
				Dst: xtest.MustParseIA("2-ff00:0:222"),
				Meta: snet.PathMetadata{
					Interfaces: []snet.PathInterface{
						{
							IA: xtest.MustParseIA("2-ff00:0:212"),
							ID: common.IFIDType(3),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:214"),
							ID: common.IFIDType(5),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:216"),
							ID: common.IFIDType(6),
						},
						{
							IA: xtest.MustParseIA("2-ff00:0:222"),
							ID: common.IFIDType(7),
						},
					},
					FabridPolicies: [][]*snet.FabridPolicyIdentifier{
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 66,
								Type:       snet.FabridGlobalPolicy,
							},
						},
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 22,
								Type:       snet.FabridLocalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 11,
								Type:       snet.FabridGlobalPolicy,
							},
						},
						{
							&snet.FabridPolicyIdentifier{
								Identifier: 66,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 22,
								Type:       snet.FabridGlobalPolicy,
							},
							&snet.FabridPolicyIdentifier{
								Identifier: 44,
								Type:       snet.FabridGlobalPolicy,
							},
						},
					},
				},
			},
			Expected: 1,
		},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.Seq != nil {
				seq, err := GetSequence(test.Path)
				assert.NoError(t, err)
				fmt.Printf("name: %s,  re: %s, seq: %s \n", name, test.Seq.restr, seq)
				//match, err :=
				//fmt.Println(.Policies())
			}
			outPaths := test.Seq.Eval([]snet.Path{test.Path})
			assert.Equal(t, test.Expected, len(outPaths))
		})
	}
	//restr := "^(?:(?:(?<hop>(?:[0-9]+)-(?:(?:[0-9]+)|(?:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+))#(?:[0-9]+),(?:[0-9]+)@\\((?:(?:(?:(?:(?=[^()]*\\b(?<pol>G44)\\b)(?=[^()]*\\b(?<pol>G66)\\b))|(?=[^()]*\\b(?<pol>G67)\\b)|(?=[^()]*\\b(?<pol>G63)\\b))))(?:G|L)(?:[0-9]+)(?:\\,(?:G|L)(?:[0-9]+))*\\)) +))*$"
	//re, err := regexp3.Compile(restr, 0)
	//
	//fmt.Println(restr)
	//assert.NoError(t, err)
	////re.ReplaceFunc("2-ff00:0:212#0,3@(G44,G66) 2-ff00:0:214#5,6@(G44,G66) 2-ff00:0:222#7,0@(G66,G44,G22,G44) 2-ff00:0:223#7,0@(G67,G44,G63,G44) ", func(match regexp3.Match) string {
	////	for _, i := range match.Groups() {
	////		for _, z := range i.Captures {
	////			fmt.Println(z.String())
	////		}
	////	}
	////	return ""
	////}, 0, -1)
	//match, err := re.FindStringMatch("2-ff00:0:212#0,3@(G44,G66) 2-ff00:0:214#5,6@(G44,G66) 2-ff00:0:222#7,0@(G66,G44,G67,G44) 2-ff00:0:223#7,0@(G63,G44,G22,G67) ")
	//assert.NoError(t, err)
	//fmt.Println(match.Policies())

	//for _, i := range match.Groups() {
	//	for _, z := range i.Captures {
	//		fmt.Println(match.String(), i.String(), z.String())
	//	}
	//}
	//type testType [][]*snet.FabridPolicyIdentifier
	//for _, test := range tests {
	//	policyVariants := make([]any, len(test.Path.Metadata().FabridPolicies))
	//	for idx, policies := range test.Path.Metadata().FabridPolicies {
	//		subsets := getAllPossibleSubsets(policies)
	//		policyVariants[idx] = subsets
	//	}
	//	c := NewCartesianProduct(policyVariants)
	//	fmt.Println(len(c.Values()))
	//}

	assert.FailNow(t, "")
}

func GetFunctionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

// Cartesian Product
type CartesianProduct struct {
	printIndicesOnly bool
	count            int
	max              int
	length           int
	shiftIndex       int
	slices           []any
	data             []int
	moduli           []int
	indices          [][]int
	values           [][]any
}

func NewCartesianProduct(inputSlices []any) *CartesianProduct {
	c := CartesianProduct{
		printIndicesOnly: false,
		count:            0,
		shiftIndex:       1,
		max:              1,
		slices:           inputSlices,
		length:           len(inputSlices),
		data:             make([]int, len(inputSlices)),
		moduli:           make([]int, len(inputSlices)),
	}
	for i, sl := range inputSlices {
		slice := reflect.ValueOf(sl)
		c.moduli[i] = slice.Len()
		c.max *= slice.Len()
	}
	// compute Cartesian and values upfront
	c.computeCartesianProduct()
	return &c
}

func (c *CartesianProduct) computeCartesianProduct() {
	for c.count < c.max {
		if c.count == 0 {
			c.count += 1
			tmp := make([]int, c.length)
			copy(tmp, c.data)
			c.indices = append(c.indices, tmp)
			c.values = append(c.values, c.getValues(tmp))
		}
		if c.count < c.max {
			// increment by "1", then take modulus
			v := (c.data[c.length-c.shiftIndex] + 1) % c.moduli[c.length-c.shiftIndex]
			c.data[c.length-c.shiftIndex] = v
			// carry the "1" if v is 0
			if v == 0 {
				for v == 0 && c.length-c.shiftIndex > 0 {
					// shift down 1 (i.e. one to the left)
					c.shiftIndex += 1
					// increment by "1", then take modulus
					v = (c.data[c.length-c.shiftIndex] + 1) % c.moduli[c.length-c.shiftIndex]
					c.data[c.length-c.shiftIndex] = v
				}
			}
			tmp := make([]int, c.length)
			copy(tmp, c.data)
			c.indices = append(c.indices, tmp)
			c.values = append(c.values, c.getValues(c.indices[c.count]))
			c.count += 1
			c.shiftIndex = 1
		}
	}
}

func (c *CartesianProduct) getValues(indices []int) []any {
	res := make([]any, 0, len(indices))
	for i, sl := range c.slices {
		slice := reflect.ValueOf(sl)
		valueInSlice := slice.Index(indices[i]).Interface()
		res = append(res, valueInSlice)
	}
	return res
}

func (c *CartesianProduct) Values() [][]any {
	return c.values
}

func (c *CartesianProduct) Indices() [][]int {
	return c.indices
}

func (c *CartesianProduct) String() string {
	if c.printIndicesOnly {
		return c.createIndicesString()
	} else {
		return c.createValuesString()
	}
}

func (c *CartesianProduct) createIndicesString() string {
	s := "\n[\n"
	for _, r := range c.indices {
		b, _ := json.Marshal(r)
		s += "  " + strings.ReplaceAll(string(b), ",", ", ") + "\n"
	}
	s += "]\n"
	return s
}

func (c *CartesianProduct) createValuesString() string {
	s := "\n[\n"
	res := []string{}
	for _, r := range c.indices {
		for k, sl := range c.slices {
			slice := reflect.ValueOf(sl)
			res = append(res, fmt.Sprintf("%+v", slice.Index(r[k]).Interface()))
		}
		s += "  [" + strings.Join(res, ", ") + "], \n"
		res = []string{}
	}
	s += "]\n"
	return s
}

// Iterators
type CartesianProductIterator struct {
	iteratorCount int
	max           int
	cartesian     *CartesianProduct
}

func (c *CartesianProduct) Iterator() *CartesianProductIterator {
	return &CartesianProductIterator{
		iteratorCount: 0,
		max:           c.max,
		cartesian:     c,
	}
}

func (cpi *CartesianProductIterator) ResetIterator() {
	cpi.iteratorCount = 0
}

func (cpi *CartesianProductIterator) NextIndices() []int {
	if !cpi.HasNext() {
		return nil
	}
	indices := cpi.cartesian.indices[cpi.iteratorCount]
	cpi.iteratorCount += 1
	return indices
}

func (cpi *CartesianProductIterator) Next() []any {
	if !cpi.HasNext() {
		return nil
	}
	indices := cpi.NextIndices()
	return cpi.cartesian.getValues(indices)
}

func (cpi *CartesianProductIterator) HasNext() bool {
	return cpi.iteratorCount < cpi.max
}
func getAllPossibleSubsets(identifiers []*snet.FabridPolicyIdentifier) [][]*snet.FabridPolicyIdentifier {
	subsets := make([][]*snet.FabridPolicyIdentifier, 0)
	size := len(identifiers)
	for i := 0; i < (1 << uint(size)); i++ {
		subset := make([]*snet.FabridPolicyIdentifier, 0)
		for j := 0; j < size; j++ {
			if i&(1<<uint(j)) != 0 {
				subset = append(subset, identifiers[j])
			}
		}
		subsets = append(subsets, subset)
	}
	return subsets
}

//func ReplaceAllStringSubmatchFunc(re *regexp2.Regexp, str string, repl func([]string) string) string {
//	result := ""
//	lastIndex := 0
//
//	for _, v := range re.FindAllSubmatchIndex([]byte(str), -1) {
//		groups := []string{}
//		for i := 0; i < len(v); i += 2 {
//			if v[i] == -1 || v[i+1] == -1 {
//				groups = append(groups, "")
//			} else {
//				groups = append(groups, str[v[i]:v[i+1]])
//			}
//		}
//
//		result += str[lastIndex:v[0]] + repl(groups)
//		lastIndex = v[1]
//	}
//
//	return result + str[lastIndex:]
//}
