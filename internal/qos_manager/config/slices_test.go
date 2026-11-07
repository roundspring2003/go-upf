package config

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func sliceConfig() Config {
	return Config{Mode: HybridHTBEDT, CapacityBps: 100_000_000, FallbackBps: 1_000_000,
		Slices: map[string]SliceConfig{
			"1-010203": {SliceBudget: SliceBudget{RateBps: 60_000_000, GBRBps: 20_000_000, BEBps: 40_000_000}},
			"1-112233": {SliceBudget: SliceBudget{RateBps: 39_000_000, GBRBps: 10_000_000, BEBps: 29_000_000}},
		}}
}
func TestSliceBudgets(t *testing.T) {
	c, err := sliceConfig().Normalize()
	require.NoError(t, err)
	require.Equal(t, uint64(60_000_000), c.Slices["1-010203"].CeilBps)
	data, err := yaml.Marshal(c)
	require.NoError(t, err)
	var decoded Config
	require.NoError(t, yaml.Unmarshal(data, &decoded))
	require.Equal(t, c, decoded)
	for _, name := range []string{"oversubscribed", "bad-key", "bad-ceil", "mixed", "override", "typo"} {
		t.Run(name, func(t *testing.T) {
			c := sliceConfig()
			s := c.Slices["1-010203"]
			switch name {
			case "oversubscribed":
				s.RateBps++
				s.BEBps++
			case "bad-key":
				c.Slices["01-010203"] = s
			case "bad-ceil":
				s.CeilBps = s.RateBps - 1
			case "mixed":
				c.GBRBps = 1
			case "override":
				s.EgressBudgets = map[string]SliceBudget{"n3": {RateBps: 61_000_000, GBRBps: 20_000_000, BEBps: 41_000_000}}
			case "typo":
				s.EgressBudgets = map[string]SliceBudget{"typo": s.SliceBudget}
			}
			c.Slices["1-010203"] = s
			normalized, err := c.Normalize()
			if name == "typo" {
				require.NoError(t, err)
				require.Error(t, normalized.ValidateEgresses([]string{"n3", "n6"}))
			} else {
				require.Error(t, err)
			}
		})
	}
	for _, key := range []string{"1", "1-010203", "255-abcdef"} {
		require.True(t, validSliceKey(key), key)
	}
	for _, key := range []string{"", "256", "1-ffffff", "1-ABCDEF", "1-123"} {
		require.False(t, validSliceKey(key), key)
	}
}
