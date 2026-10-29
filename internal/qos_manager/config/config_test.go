package config

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestModeConfiguration(t *testing.T) {
	for _, mode := range []Mode{PerFlowHTB, SharedHTB, SharedHTBEDT} {
		c, err := (Config{Mode: mode, CapacityBps: 30_000_000, GBRBps: 20_000_000, BEBps: 9_000_000, FallbackBps: 1_000_000}).Normalize()
		require.NoError(t, err)
		require.Equal(t, mode, c.Mode)
		require.Equal(t, uint32(1000), c.HorizonMS)
	}
	for _, c := range []Config{{Mode: "shared-htb-typo"}, {CapacityBps: 30_000_000, GBRBps: 31_000_000}, {HorizonMS: 10001}, {CapacityBps: 1}} {
		_, err := c.Normalize()
		require.Error(t, err)
	}
}

func TestEgressBudgets(t *testing.T) {
	cfg, err := (Config{CapacityBps: 30_000_000, EgressBudgets: map[string]ClassBudget{
		"n6": {GBRBps: 18_000_000, BEBps: 11_000_000, FallbackBps: 1_000_000},
		"n3": {GBRBps: 0, BEBps: 29_000_000, FallbackBps: 1_000_000},
	}}).Normalize()
	require.NoError(t, err)
	require.NoError(t, cfg.ValidateEgresses([]string{"n3", "n6"}))
	require.Error(t, cfg.ValidateEgresses([]string{"n3"}))
	require.Equal(t, uint64(18_000_000), cfg.BudgetFor("n6").GBRBps)
	require.Zero(t, cfg.BudgetFor("n3").GBRBps)
	for _, b := range []ClassBudget{
		{GBRBps: 31_000_000, BEBps: 1, FallbackBps: 1},
		{GBRBps: 18_000_000, BEBps: 12_000_000},
		{},
	} {
		_, err := (Config{CapacityBps: 30_000_000, EgressBudgets: map[string]ClassBudget{"n6": b}}).Normalize()
		require.Error(t, err)
	}
}
