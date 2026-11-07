package tc

import (
	"strings"
	"testing"

	qosconfig "github.com/free5gc/go-upf/internal/qos_manager/config"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/stretchr/testify/require"
)

func testSliceConfig(mode qosconfig.Mode) qosconfig.Config {
	return qosconfig.Config{Mode: mode, CapacityBps: 100_000_000, FallbackBps: 1_000_000, Slices: map[string]qosconfig.SliceConfig{
		"1-010203": {SliceBudget: qosconfig.SliceBudget{RateBps: 60_000_000, GBRBps: 20_000_000, BEBps: 40_000_000}},
		"1-112233": {SliceBudget: qosconfig.SliceBudget{RateBps: 39_000_000, GBRBps: 10_000_000, BEBps: 29_000_000}},
	}}
}
func slicePolicy(id uint32, slice string, gbr uint64) rules.Policy {
	p := testPolicy(id, "n6")
	p.Target.Slice = slice
	p.Rates = []rules.QoSRate{{QERID: 1, GBRBps: gbr, MBRBps: 80_000_000}}
	return p
}
func TestSliceIsolationAndAdmission(t *testing.T) {
	for _, mode := range []qosconfig.Mode{qosconfig.HybridHTBEDT, qosconfig.PerFlowHTBEDT} {
		t.Run(string(mode), func(t *testing.T) {
			var commands []string
			m, err := openClasses([]string{"n3", "n6"}, func(args ...string) error { commands = append(commands, strings.Join(args, " ")); return nil }, testSliceConfig(mode))
			require.NoError(t, err)
			defer m.Close()
			put := func(p rules.Policy) uint32 {
				t.Helper()
				id, _, err := m.Prepare(p)
				require.NoError(t, err)
				m.Commit(p.ID)
				return id
			}
			a := slicePolicy(1, "1-010203", 10_000_000)
			id := put(a)
			require.Equal(t, uint16(17), m.active[a.ID].parent)
			require.Equal(t, uint64(60_000_000), m.flows[keyFor(a)].ceil, "slice ceiling caps the leaf")
			alias := a
			alias.ID = 2
			alias.Key.PDRID = 2
			require.Equal(t, id, put(alias))
			b := slicePolicy(3, "1-010203", 10_000_000)
			b.Key.SEID = 2
			b.QFI = a.QFI
			put(b)
			require.Equal(t, uint64(20_000_000), m.totals["n6"][17], "same QFI in different sessions reserves separately")
			over := slicePolicy(4, "1-010203", 1_000_000)
			before := len(commands)
			require.Error(t, m.validateChanges([]rules.Policy{over}, nil))
			require.Len(t, commands, before, "validation is read-only")
			_, _, err = m.Prepare(over)
			require.Error(t, err)
			other := slicePolicy(5, "1-112233", 10_000_000)
			put(other)
			require.Equal(t, uint16(20), m.active[other.ID].parent)
			beA := slicePolicy(6, "1-010203", 0)
			beB := slicePolicy(7, "1-112233", 0)
			beAID, beBID := put(beA), put(beB)
			require.NotEqual(t, beAID, beBID)
			require.NoError(t, m.Delete(beA.ID))
			require.True(t, m.used["n6"][18], "static slice leaf survives policy deletion")
			unknown := slicePolicy(8, "", 0)
			require.Error(t, m.validateChanges([]rules.Policy{unknown}, nil))
			unknown.Target.Slice = "9"
			_, _, err = m.Prepare(unknown)
			require.Error(t, err)
			require.NoError(t, m.validateChanges([]rules.Policy{over}, []rules.PDRKey{b.Key}))
			require.NoError(t, m.Delete(b.ID))
			put(over)
			require.NoError(t, m.Delete(a.ID))
			require.Equal(t, uint64(11_000_000), m.totals["n6"][17])
			require.NoError(t, m.Delete(alias.ID))
			require.Equal(t, uint64(1_000_000), m.totals["n6"][17])
		})
	}
}
func TestSliceClassExhaustion(t *testing.T) {
	m, err := openClasses([]string{"n6"}, func(...string) error { return nil }, testSliceConfig(qosconfig.HybridHTBEDT))
	require.NoError(t, err)
	for i := uint32(firstFlowMinor); i < 0xffff; i++ {
		m.used["n6"][uint16(i)] = true
	}
	_, _, err = m.Prepare(slicePolicy(1, "1-010203", 1_000_000))
	require.ErrorContains(t, err, "exhausted")
}

func TestSliceAdmissionPublicationOrder(t *testing.T) {
	m, err := openClasses([]string{"n6"}, func(...string) error { return nil }, testSliceConfig(qosconfig.HybridHTBEDT))
	require.NoError(t, err)
	a, b := slicePolicy(1, "1-010203", 10_000_000), slicePolicy(2, "1-010203", 10_000_000)
	for _, p := range []rules.Policy{a, b} {
		_, _, err = m.Prepare(p)
		require.NoError(t, err)
		m.Commit(p.ID)
	}
	a.Rates = []rules.QoSRate{{QERID: 1, GBRBps: 15_000_000, MBRBps: 20_000_000}}
	b.Rates = []rules.QoSRate{{QERID: 1, GBRBps: 5_000_000, MBRBps: 20_000_000}}
	require.Error(t, m.validateChanges([]rules.Policy{a, b}, nil), "reject temporary over-admission before forwarding")
	require.NoError(t, m.validateChanges([]rules.Policy{b, a}, nil))
	require.Equal(t, uint64(20_000_000), m.totals["n6"][17], "validation must not mutate live totals")
	for _, p := range []rules.Policy{b, a} {
		_, _, err = m.Prepare(p)
		require.NoError(t, err)
		m.Commit(p.ID)
	}
}
