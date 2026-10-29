package main

import (
	"os"
	"path/filepath"
	"testing"

	qosconfig "github.com/free5gc/go-upf/internal/qos_manager/config"
	"github.com/free5gc/go-upf/pkg/factory"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestCalculateCountsQoSFlowsOncePerDirection(t *testing.T) {
	a := flow{Session: "ue1", QFI: 8, GBRULBps: 10_000_000, GBRDLBps: 5_000_000}
	b := flow{Session: "ue1", QFI: 9, GBRULBps: 8_000_000, GBRDLBps: 4_000_000}
	plan, err := calculate(scenario{CapacityBps: 30_000_000, FallbackBps: 1_000_000, Flows: []flow{a, b, a}})
	require.NoError(t, err)
	require.Equal(t, 2, plan.UniqueFlows)
	require.Equal(t, qosconfig.ClassBudget{GBRBps: 18_000_000, BEBps: 11_000_000, FallbackBps: 1_000_000}, plan.Uplink)
	require.Equal(t, qosconfig.ClassBudget{GBRBps: 9_000_000, BEBps: 20_000_000, FallbackBps: 1_000_000}, plan.Downlink)
	// Reusing a QFI in a different session denotes another QoS flow.
	otherSession := a
	a.Session = "ue2"
	plan, err = calculate(scenario{CapacityBps: 30_000_000, FallbackBps: 1_000_000, Flows: []flow{a, otherSession}})
	require.NoError(t, err)
	require.Equal(t, 2, plan.UniqueFlows)
	require.Equal(t, uint64(20_000_000), plan.Uplink.GBRBps)
}

func TestCalculateRejectsInvalidRounds(t *testing.T) {
	for name, flows := range map[string][]flow{
		"empty":      nil,
		"no session": {{QFI: 8}},
		"bad QFI":    {{Session: "ue1", QFI: 64}},
		"UL over":    {{Session: "ue1", QFI: 8, GBRULBps: 30_000_000}},
		"DL no BE":   {{Session: "ue1", QFI: 8, GBRDLBps: 29_000_000}},
		"overflow":   {{Session: "ue1", QFI: 8, GBRULBps: ^uint64(0)}},
		"conflict":   {{Session: "ue1", QFI: 8, GBRULBps: 10}, {Session: "ue1", QFI: 8, GBRULBps: 20}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := calculate(scenario{CapacityBps: 30_000_000, FallbackBps: 1_000_000, Flows: flows})
			require.Error(t, err)
		})
	}
}

func TestPreparedModesShareBudgetsAndPreserveUPFConfiguration(t *testing.T) {
	base, err := os.ReadFile("../../config/upfcfg.yaml")
	require.NoError(t, err)
	s := scenario{CapacityBps: 30_000_000, FallbackBps: 1_000_000, Flows: []flow{
		{Session: "ue1", QFI: 8, GBRULBps: 10_000_000, GBRDLBps: 5_000_000},
		{Session: "ue1", QFI: 9, GBRULBps: 8_000_000, GBRDLBps: 4_000_000},
	}}
	files, plan, err := prepare(base, s)
	require.NoError(t, err)
	require.Len(t, files, 4)
	var original factory.Config
	require.NoError(t, yaml.UnmarshalStrict(base, &original))
	for _, mode := range []qosconfig.Mode{qosconfig.PerFlowHTB, qosconfig.SharedHTB, qosconfig.SharedHTBEDT} {
		path := filepath.Join(t.TempDir(), "upfcfg.yaml")
		require.NoError(t, os.WriteFile(path, files[string(mode)+".yaml"], 0o600))
		cfg, err := factory.ReadConfig(path)
		require.NoError(t, err)
		require.Equal(t, mode, cfg.QoS.Mode)
		require.Equal(t, original.Pfcp, cfg.Pfcp)
		require.Equal(t, original.Gtpu, cfg.Gtpu)
		require.Equal(t, original.DnnList, cfg.DnnList)
		normalized, err := cfg.QoS.Config.Normalize()
		require.NoError(t, err)
		require.Equal(t, plan.Uplink, normalized.BudgetFor(plan.N6Egress))
		require.Equal(t, plan.Downlink, normalized.BudgetFor(plan.N3Egress))
	}
}

func TestPrepareWithoutGBRAndAmbiguousEgress(t *testing.T) {
	s := scenario{CapacityBps: 30_000_000, FallbackBps: 1_000_000, Flows: []flow{{Session: "ue1", QFI: 8}}}
	_, plan, err := prepare([]byte("qos:\n  n3Egress: n3\n  n6Egress: n6\n"), s)
	require.NoError(t, err)
	require.Zero(t, plan.Uplink.GBRBps)
	require.Equal(t, uint64(29_000_000), plan.Uplink.BEBps)
	_, _, err = prepare([]byte("qos:\n  n3Egress: same\n  n6Egress: same\n"), s)
	require.Error(t, err)
}
