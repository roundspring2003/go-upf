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
	for _, mode := range []qosconfig.Mode{qosconfig.PerFlowHTB, qosconfig.PerFlowHTBEDT, qosconfig.SharedHTB, qosconfig.SharedHTBEDT, qosconfig.HybridHTBEDT} {
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
			if mode.PerFlowClass(false) {
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
			if !mode.PerFlowClass(false) {
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
	require.Contains(t, commands, "class change dev n6 parent e001:2 classid e001:10 htb rate 2000000bit ceil 5000000bit prio 0 quantum 1514 burst 2600 cburst 4100")
}

func TestHybridMembershipTransitionsAndAdmission(t *testing.T) {
	var commands []string
	m, err := openClasses([]string{"n6"}, func(args ...string) error {
		commands = append(commands, strings.Join(args, " "))
		return nil
	}, qosconfig.Config{Mode: qosconfig.HybridHTBEDT, CapacityBps: 30_000_000,
		GBRBps: 18_000_000, BEBps: 11_000_000, FallbackBps: 1_000_000})
	require.NoError(t, err)
	defer m.Close()
	require.Contains(t, commands, "qdisc add dev n6 parent e001:3 fq limit 10000 flow_limit 1000 horizon 1000ms horizon_drop")
	for _, cmd := range commands {
		require.NotContains(t, cmd, "parent e001:2 fq")
	}
	put := func(p rules.Policy) uint32 {
		t.Helper()
		id, _, err := m.Prepare(p)
		require.NoError(t, err)
		m.Commit(p.ID)
		return id
	}
	a, b, c := testPolicy(1, "n6"), testPolicy(2, "n6"), testPolicy(3, "n6")
	a.Rates = []rules.QoSRate{{QERID: 1, GBRBps: 10_000_000, MBRBps: 20_000_000}}
	b.Rates = []rules.QoSRate{{QERID: 2, GBRBps: 8_000_000, MBRBps: 20_000_000}}
	aID, bID := put(a), put(b)
	require.NotEqual(t, aID, bID)
	require.Equal(t, uint64(18_000_000), m.totals["n6"][2])
	require.Equal(t, uint32(0xe0010003), put(c))
	d := testPolicy(4, "n6")
	require.Equal(t, put(c), put(d))
	extra := testPolicy(5, "n6")
	extra.Rates = []rules.QoSRate{{QERID: 5, GBRBps: 1_000_000}}
	_, _, err = m.Prepare(extra)
	require.Error(t, err, "hybrid must reject over-admitted dedicated GBR")
	// A second PDR in A's QoS flow shares its class and consumes no new GBR.
	alias := a
	alias.ID, alias.Key.PDRID = 6, 6
	require.Equal(t, aID, put(alias))
	require.Equal(t, uint64(18_000_000), m.totals["n6"][2])
	require.NoError(t, m.Delete(alias.ID))
	// A moves to shared BE; the old owned class and its reservation disappear.
	a.Rates = nil
	require.Equal(t, uint32(0xe0010003), put(a))
	require.Len(t, m.flows, 1)
	require.Equal(t, uint64(8_000_000), m.totals["n6"][2])
	// A moves back to GBR, including a publication rollback before commit.
	a.Rates = []rules.QoSRate{{QERID: 1, GBRBps: 10_000_000, MBRBps: 20_000_000}}
	_, created, err := m.Prepare(a)
	require.NoError(t, err)
	require.True(t, created)
	require.NoError(t, m.Rollback(a.ID, created))
	require.Equal(t, uint32(0xe0010003), m.active[a.ID].id())
	put(a)
	for _, id := range []uint32{a.ID, b.ID, c.ID, d.ID} {
		require.NoError(t, m.Delete(id))
	}
	require.Empty(t, m.flows)
	require.Empty(t, m.active)
	require.Zero(t, m.totals["n6"][2])
	for _, cmd := range commands {
		require.NotContains(t, cmd, "class del dev n6 classid e001:3")
	}
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
	for _, mode := range []qosconfig.Mode{qosconfig.PerFlowHTB, qosconfig.PerFlowHTBEDT, qosconfig.SharedHTB, qosconfig.SharedHTBEDT, qosconfig.HybridHTBEDT} {
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
			require.Contains(t, commands, "class add dev n6 parent e001:1 classid e001:2 htb rate 18000000bit ceil 30000000bit prio 0 quantum 1514 burst 10600 cburst 16600")
			require.Contains(t, commands, "class add dev n3 parent e001:1 classid e001:2 htb rate 9000000bit ceil 30000000bit prio 0 quantum 1514 burst 6100 cburst 16600")
			require.Contains(t, commands, "class add dev n6 parent e001:1 classid e001:3 htb rate 11000000bit ceil 30000000bit prio 1 quantum 1514 burst 7100 cburst 16600")
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
			if !mode.PerFlowClass(true) {
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

func TestHTBFourMillisecondCredit(t *testing.T) {
	var commands []string
	m, err := openClasses([]string{"n6"}, func(args ...string) error {
		commands = append(commands, strings.Join(args, " "))
		return nil
	}, qosconfig.Config{Mode: qosconfig.HybridHTBEDT, CapacityBps: 100_000_000,
		GBRBps: 60_000_000, BEBps: 39_000_000, FallbackBps: 1_000_000})
	require.NoError(t, err)
	defer m.Close()
	require.Contains(t, commands, "class add dev n6 parent e001: classid e001:1 htb rate 100000000bit ceil 100000000bit prio 0 quantum 1514 burst 51600 cburst 51600")
	require.Contains(t, commands, "class add dev n6 parent e001:1 classid e001:2 htb rate 60000000bit ceil 100000000bit prio 0 quantum 1514 burst 31600 cburst 51600")
	p := testPolicy(1, "n6")
	p.Rates = []rules.QoSRate{{QERID: 1, GBRBps: 35_000_000, MBRBps: 70_000_000}}
	_, _, err = m.Prepare(p)
	require.NoError(t, err)
	require.Contains(t, commands, "class add dev n6 parent e001:2 classid e001:10 htb rate 35000000bit ceil 70000000bit prio 0 quantum 1514 burst 19100 cburst 36600")
	// Preserve a packet allowance even at low rates, rounding credit upward.
	require.Equal(t, uint64(1601), htbBurstBytes(1000))
	require.Equal(t, uint64(1602), htbBurstBytes(2001))
	require.Equal(t, uint64(500_001_600), htbBurstBytes(1_000_000_000_000))
}
