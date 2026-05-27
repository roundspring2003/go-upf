package forwarder

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildQoSCPUPools(t *testing.T) {
	t.Run("exact 1:1:2 allocation", func(t *testing.T) {
		pools, err := buildQoSCPUPools(6, 2)
		require.NoError(t, err)

		assert.Equal(t, qosCPUPool{StartCPU: 2, CPUCount: 1}, pools[QoSClassBackground])
		assert.Equal(t, qosCPUPool{StartCPU: 3, CPUCount: 1}, pools[QoSClassLatencySensitive])
		assert.Equal(t, qosCPUPool{StartCPU: 4, CPUCount: 2}, pools[QoSClassStandard])
	})

	t.Run("remainder favors standard then background", func(t *testing.T) {
		pools, err := buildQoSCPUPools(8, 2)
		require.NoError(t, err)

		assert.Equal(t, qosCPUPool{StartCPU: 2, CPUCount: 2}, pools[QoSClassBackground])
		assert.Equal(t, qosCPUPool{StartCPU: 4, CPUCount: 1}, pools[QoSClassLatencySensitive])
		assert.Equal(t, qosCPUPool{StartCPU: 5, CPUCount: 3}, pools[QoSClassStandard])
	})
}

func TestBuildQoSCPUPoolsRejectsInvalidCPUCounts(t *testing.T) {
	testcases := []struct {
		name     string
		totalCPU int
		reserved uint32
	}{
		{name: "zero reserved", totalCPU: 8, reserved: 0},
		{name: "reserved all CPUs", totalCPU: 4, reserved: 4},
		{name: "too few data-plane CPUs", totalCPU: 5, reserved: 2},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildQoSCPUPools(tc.totalCPU, tc.reserved)
			assert.Error(t, err)
		})
	}
}
