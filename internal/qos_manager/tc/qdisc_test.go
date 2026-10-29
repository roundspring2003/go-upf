package tc

import (
	"errors"
	"slices"
	"strings"
	"testing"

	qosconfig "github.com/free5gc/go-upf/internal/qos_manager/config"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/stretchr/testify/require"
)

func testPolicy(id uint32, iface string) rules.Policy {
	qfi := uint8(id)
	return rules.Policy{ID: id, Key: rules.PDRKey{SEID: 1, PDRID: uint16(id)}, QFI: &qfi, Direction: rules.Uplink, Target: &rules.Target{Egress: iface}}
}
func TestClassModesAndSharedDeletion(t *testing.T) {
	for _, mode := range []qosconfig.Mode{qosconfig.PerFlowHTB, qosconfig.SharedHTB, qosconfig.SharedHTBEDT} {
		t.Run(string(mode), func(t *testing.T) {
			var commands []string
			m, err := openClasses([]string{"n3", "n6"}, func(args ...string) error { commands = append(commands, strings.Join(args, " ")); return nil }, qosconfig.Config{Mode: mode})
			require.NoError(t, err)
			defer m.Close()
			require.Contains(t, commands, "qdisc add dev n3 root handle e001: htb default 4")
			a, _, err := m.Prepare(testPolicy(7, "n6"))
			require.NoError(t, err)
			m.Commit(7)
			b, _, err := m.Prepare(testPolicy(8, "n6"))
			require.NoError(t, err)
			m.Commit(8)
			if mode == qosconfig.PerFlowHTB {
				require.NotEqual(t, a, b)
			} else {
				require.Equal(t, a, b)
				require.Equal(t, uint32(0xe0010003), a)
			}
			same := testPolicy(9, "n6")
			same.QFI = testPolicy(7, "n6").QFI
			c, _, err := m.Prepare(same)
			require.NoError(t, err)
			m.Commit(9)
			require.Equal(t, a, c, "PDRs in one flow share their class")
			commands = nil
			require.NoError(t, m.Delete(7))
			require.Equal(t, c, m.active[9].id())
			require.False(t, slices.ContainsFunc(commands, func(cmd string) bool { return strings.HasPrefix(cmd, "class del") }))
			require.NoError(t, m.Delete(9))
			require.NoError(t, m.Delete(8))
			if mode != qosconfig.PerFlowHTB {
				require.Empty(t, commands, "shared leaves survive the last PDR")
			}
		})
	}
}
func TestClassRollbackAndRateUpdate(t *testing.T) {
	var commands []string
	m, err := openClasses([]string{"n6"}, func(args ...string) error { commands = append(commands, strings.Join(args, " ")); return nil })
	require.NoError(t, err)
	p := testPolicy(7, "n6")
	p.Rates = []rules.QoSRate{{QERID: 1, MBRBps: 5_000_000, GBRBps: 2_000_000}}
	id, created, err := m.Prepare(p)
	require.NoError(t, err)
	require.True(t, created)
	require.NoError(t, m.Rollback(p.ID, created))
	require.Empty(t, m.active)
	id, _, err = m.Prepare(p)
	require.NoError(t, err)
	m.Commit(p.ID)
	p.Rates[0].MBRBps = 6_000_000
	updated, created, err := m.Prepare(p)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, id, updated)
	require.NoError(t, m.Rollback(p.ID, created))
	require.Contains(t, commands, "class change dev n6 parent e001:2 classid e001:10 htb rate 2000000bit ceil 5000000bit prio 0 quantum 1514")
}
func TestClassSetupFailureRemovesOnlyCreatedRoots(t *testing.T) {
	var commands []string
	_, err := openClasses([]string{"n3", "n6"}, func(args ...string) error {
		cmd := strings.Join(args, " ")
		commands = append(commands, cmd)
		if cmd == "qdisc add dev n6 root handle e001: htb default 4" {
			return errors.New("owned root")
		}
		return nil
	})
	require.Error(t, err)
	var deleted []string
	for _, cmd := range commands {
		if strings.HasPrefix(cmd, "qdisc del") {
			deleted = append(deleted, cmd)
		}
	}
	require.Equal(t, []string{"qdisc del dev n3 root handle e001:"}, deleted)
}

func TestFixedDirectionalBudgetsAcrossModes(t *testing.T) {
	for _, mode := range []qosconfig.Mode{qosconfig.PerFlowHTB, qosconfig.SharedHTB, qosconfig.SharedHTBEDT} {
		t.Run(string(mode), func(t *testing.T) {
			var commands []string
			cfg := qosconfig.Config{Mode: mode, CapacityBps: 30_000_000, EgressBudgets: map[string]qosconfig.ClassBudget{
				"n6": {GBRBps: 18_000_000, BEBps: 11_000_000, FallbackBps: 1_000_000},
				"n3": {GBRBps: 9_000_000, BEBps: 20_000_000, FallbackBps: 1_000_000},
			}}
			m, err := openClasses([]string{"n3", "n6"}, func(args ...string) error {
				commands = append(commands, strings.Join(args, " "))
				return nil
			}, cfg)
			require.NoError(t, err)
			defer m.Close()
			require.Contains(t, commands, "class add dev n6 parent e001:1 classid e001:2 htb rate 18000000bit ceil 30000000bit prio 0 quantum 1514")
			require.Contains(t, commands, "class add dev n3 parent e001:1 classid e001:2 htb rate 9000000bit ceil 30000000bit prio 0 quantum 1514")
			require.Contains(t, commands, "class add dev n6 parent e001:1 classid e001:3 htb rate 11000000bit ceil 30000000bit prio 1 quantum 1514")
			commands = nil
			for i, rate := range []uint64{10_000_000, 8_000_000} {
				p := testPolicy(uint32(i+1), "n6")
				p.Rates = []rules.QoSRate{{QERID: uint32(i + 1), GBRBps: rate, MBRBps: 20_000_000}}
				_, _, err := m.Prepare(p)
				require.NoError(t, err)
				m.Commit(p.ID)
			}
			// Reversing/removing rules never changes the shared service rate.
			require.NoError(t, m.Delete(1))
			require.NoError(t, m.Delete(2))
			for _, cmd := range commands {
				require.NotContains(t, cmd, "classid e001:2 ")
				require.NotContains(t, cmd, "classid e001:3 ")
			}
			if mode != qosconfig.PerFlowHTB {
				require.Empty(t, commands)
			}
			// The other direction must enforce its own, smaller budget.
			p := testPolicy(3, "n3")
			p.Rates = []rules.QoSRate{{QERID: 3, GBRBps: 10_000_000}}
			_, _, err = m.Prepare(p)
			require.Error(t, err)
		})
	}
}

func TestRoundWithoutGBRDoesNotCreateZeroRateClass(t *testing.T) {
	var commands []string
	cfg := qosconfig.Config{Mode: qosconfig.SharedHTB, CapacityBps: 30_000_000,
		EgressBudgets: map[string]qosconfig.ClassBudget{"n6": {BEBps: 29_000_000, FallbackBps: 1_000_000}}}
	m, err := openClasses([]string{"n6"}, func(args ...string) error {
		commands = append(commands, strings.Join(args, " "))
		return nil
	}, cfg)
	require.NoError(t, err)
	defer m.Close()
	for _, cmd := range commands {
		require.NotContains(t, cmd, "classid e001:2 ")
		require.NotContains(t, cmd, "parent e001:2 fq")
	}
	_, _, err = m.Prepare(testPolicy(1, "n6"))
	require.NoError(t, err)
	m.Commit(1)
	p := testPolicy(2, "n6")
	p.Rates = []rules.QoSRate{{QERID: 2, GBRBps: 1_000_000}}
	_, _, err = m.Prepare(p)
	require.Error(t, err)
}
