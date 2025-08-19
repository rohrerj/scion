// Copyright 2025 ETH Zurich
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

package collector

type Collector interface {
	Collect(int, int, int, int)
}

type LocalCollector struct {
}

type RemoteCollector struct {
	//used for remote collector application, currently not implemented
}

func (c *LocalCollector) Collect(ingress int, egress int, time_window int, hash int) {
	v := c.receive(ingress, egress, time_window, hash)
	e := c.retrieve_existing(ingress, egress, time_window)
	c.save(c.merge(e, v))
	if c.isWindowClosing(time_window) {
		c.persist(time_window)
	}
}

func (c *LocalCollector) receive(ingress int, egress int, time_window int, hash int) int {
	return 0
}

func (c *LocalCollector) retrieve_existing(ingress int, egress int, time_window int) int {
	return 0
}

func (c *LocalCollector) merge(e int, v int) int {
	return e ^ v
}

func (c *LocalCollector) save(merged_ev int) {

}

func (c *LocalCollector) isWindowClosing(window int) bool {
	return false
}

func (c *LocalCollector) persist(window int) {

}
