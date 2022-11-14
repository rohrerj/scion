// Copyright 2022 ETH Zurich
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

package processing_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/coligate/processing"
	"github.com/scionproto/scion/go/pkg/coligate/config"
)

func getColigateConfiguration() *config.ColigateConfig {
	cfg := &config.ColigateConfig{}
	cfg.NumBitsForGatewayId = 1
	cfg.NumBitsForWorkerId = 8
	cfg.NumBitsForPerWorkerCounter = 23
	cfg.NumWorkers = 8
	cfg.MaxQueueSizePerWorker = 256
	cfg.Salt = ""
	cfg.ColibriGatewayID = 1
	return cfg
}

func TestMasking(t *testing.T) {
	worker := processing.Worker{}
	err := worker.InitWorker(getColigateConfiguration(), 1, 1)
	require.NoError(t, err)
	expectedInitialValue := uint32(2147483648 + 8388608) //2^31 + 2^23
	assert.Equal(t, expectedInitialValue, worker.CoreIdCounter)

	worker.CoreIdCounter = worker.InitialCoreIdCounter | (worker.CoreIdCounter+1)%(1<<worker.NumCounterBits)
	assert.Equal(t, expectedInitialValue+1, worker.CoreIdCounter)

	worker.CoreIdCounter = worker.InitialCoreIdCounter | (worker.CoreIdCounter+1)%(1<<worker.NumCounterBits)
	assert.Equal(t, expectedInitialValue+2, worker.CoreIdCounter)

	worker.CoreIdCounter = expectedInitialValue + 8388607 //+ 2^23 -1
	worker.CoreIdCounter = worker.InitialCoreIdCounter | (worker.CoreIdCounter+1)%(1<<worker.NumCounterBits)
	assert.Equal(t, expectedInitialValue, worker.CoreIdCounter)
}
