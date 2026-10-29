package tc

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	qosconfig "github.com/free5gc/go-upf/internal/qos_manager/config"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// This loads the real program and executes it with BPF_PROG_TEST_RUN. It does
// not attach a link, create a network device, or touch a production qdisc.
func TestEDTKernel(t *testing.T) {
	spec := qosEgressSpec()
	addEDT(spec, 1000)
	objects, err := ebpf.NewCollection(spec)
	if os.Geteuid() != 0 && (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)) {
		t.Skipf("BPF requires privileges: %v", err)
	}
	require.NoError(t, err)
	defer objects.Close()
	classes, err := openClasses([]string{"test"}, func(...string) error { return nil }, qosconfig.Config{Mode: qosconfig.SharedHTBEDT})
	require.NoError(t, err)
	e := &TCEgress{objects: objects, interfaces: map[string]uint32{"test": 1}, classes: classes, rates: newRateManager(objects)}
	p := testPolicy(1, "test")
	p.Rates = []rules.QoSRate{{QERID: 7, MBRBps: 8000}, {QERID: 9, MBRBps: 4000}}
	a, err := e.PutQoSPolicy(p)
	require.NoError(t, err)
	p2 := testPolicy(2, "test")
	p2.Rates = []rules.QoSRate{{QERID: 8, MBRBps: 16000}, {QERID: 9, MBRBps: 4000}}
	b, err := e.PutQoSPolicy(p2)
	require.NoError(t, err)
	require.Equal(t, a, b)
	run := func(id uint32) (uint32, uint64) {
		t.Helper()
		ctx := make([]byte, 192)
		binary.NativeEndian.PutUint32(ctx[skbMark:], id)
		binary.NativeEndian.PutUint32(ctx[skbIfindex:], 1)
		out := make([]byte, len(ctx))
		data := make([]byte, 64)
		data[12] = 8
		data[14] = 0x45
		verdict, err := objects.Programs["qos_egress"].Run(&ebpf.RunOptions{Data: data, Context: ctx, ContextOut: out, Repeat: 1})
		require.NoError(t, err)
		return verdict, binary.NativeEndian.Uint64(out[skbTstamp:])
	}
	verdict, first := run(1)
	require.Equal(t, uint32(0xffffffff), verdict)
	require.NotZero(t, first)
	verdict, second := run(2)
	require.Equal(t, uint32(0xffffffff), verdict)
	require.GreaterOrEqual(t, second, first+128_000_000, "shared QER cap must apply across PDRs")
	old := e.rates.policies[1]
	p.Rates[0].MBRBps = 16000
	_, err = e.PutQoSPolicy(p)
	require.NoError(t, err)
	require.Equal(t, old.Key, e.rates.policies[1].Key)
	verdict, third := run(1)
	require.Equal(t, uint32(0xffffffff), verdict)
	require.GreaterOrEqual(t, third, second+128_000_000, "rate updates must preserve the shared clock")
	// The same numeric QER ID in another session must have its own clock.
	other := testPolicy(3, "test")
	other.Key.SEID = 2
	other.Rates = []rules.QoSRate{{QERID: 9, MBRBps: 4000}}
	_, err = e.PutQoSPolicy(other)
	require.NoError(t, err)
	require.NotEqual(t, e.rates.policies[1].Key, e.rates.policies[3].Key)
	// Seed a definitely-future clock beyond the horizon. Dropping must not reserve
	// more time (otherwise overload could keep itself blocked forever).
	key := e.rates.policies[1].Key
	var state rateRuntime
	require.NoError(t, objects.Maps["qos_runtime"].LookupWithFlags(key, &state, ebpf.LookupLock))
	for n := range state.Next {
		state.Next[n] = third + 20_000_000_000
	}
	require.NoError(t, objects.Maps["qos_runtime"].Update(key, state, ebpf.UpdateLock))
	verdict, _ = run(1)
	require.Equal(t, uint32(2), verdict)
	var after rateRuntime
	require.NoError(t, objects.Maps["qos_runtime"].LookupWithFlags(key, &after, ebpf.LookupLock))
	require.Equal(t, state.Next, after.Next)
	var drops [][3]uint64
	require.NoError(t, objects.Maps["qos_drops"].Lookup(uint32(1), &drops))
	var horizonDrops uint64
	for _, d := range drops {
		horizonDrops += d[1]
	}
	require.Equal(t, uint64(1), horizonDrops)
	require.NoError(t, e.DeleteQoSPolicy(1))
	require.NoError(t, objects.Maps["qos_runtime"].LookupWithFlags(key, &after, ebpf.LookupLock), "another PDR still uses this session clock")
	require.NoError(t, e.DeleteQoSPolicy(2))
	require.ErrorIs(t, objects.Maps["qos_runtime"].LookupWithFlags(key, &after, ebpf.LookupLock), ebpf.ErrKeyNotExist)
	require.NoError(t, e.DeleteQoSPolicy(3))
	require.Empty(t, e.rates.sessions)
}
