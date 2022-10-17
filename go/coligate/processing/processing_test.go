package processing_test

import (
	"testing"

	"github.com/scionproto/scion/go/coligate/processing"
	"github.com/scionproto/scion/go/pkg/coligate/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getColigateConfiguration() *config.ColigateConfig {
	cfg := &config.ColigateConfig{}
	cfg.NumBitsForGatewayId = 1
	cfg.NumBitsForWorkerId = 8
	cfg.NumBitsForPerWorkerCounter = 23
	cfg.NumWorkers = 8
	cfg.MaxQueueSizePerThread = 256
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
