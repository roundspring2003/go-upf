package tc

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Does not attach to a real interface or change qdiscs. BPF_PROG_TEST_RUN
// verifies packet behavior in the kernel when CAP_BPF/CAP_NET_ADMIN is available.
func TestQoSEgressKernel(t *testing.T) {
	objects, err := ebpf.NewCollection(qosEgressSpec())
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("kernel BPF test requires privileges: %v", err)
	}
	require.NoError(t, err)
	defer objects.Close()
	lo, err := net.InterfaceByName("lo")
	require.NoError(t, err)
	classes, err := openClasses([]string{"test"}, func(...string) error { return nil })
	require.NoError(t, err)
	e := &TCEgress{objects: objects, interfaces: map[string]uint32{"test": uint32(lo.Index)}, classes: classes}
	p := rules.Policy{ID: 7, Target: &rules.Target{Egress: "test"}}
	classID, err := e.PutQoSPolicy(p)
	require.NoError(t, err)
	require.Equal(t, uint32(0xe0010010), classID)
	run := func(mark, priority uint32) uint32 {
		t.Helper()
		ctx := make([]byte, 192)
		binary.NativeEndian.PutUint32(ctx[skbMark:], mark)
		binary.NativeEndian.PutUint32(ctx[skbPriority:], priority)
		binary.NativeEndian.PutUint32(ctx[skbIfindex:], uint32(lo.Index))
		out := make([]byte, len(ctx))
		data := make([]byte, 64)
		data[12] = 0x08
		data[14] = 0x45
		result, err := objects.Programs["qos_egress"].Run(&ebpf.RunOptions{Data: data, Context: ctx, ContextOut: out, Repeat: 1})
		require.NoError(t, err)
		require.Equal(t, uint32(0xffffffff), result)
		require.Equal(t, mark, binary.NativeEndian.Uint32(out[skbMark:]))
		return binary.NativeEndian.Uint32(out[skbPriority:])
	}
	stats := func() qosCounters {
		var values []qosCounters
		require.NoError(t, objects.Maps["qos_stats"].Lookup(uint32(7), &values))
		var sum qosCounters
		for _, v := range values {
			sum.Packets += v.Packets
			sum.Bytes += v.Bytes
		}
		return sum
	}
	require.Equal(t, classID, run(0xab000007, 42))
	first := stats()
	require.GreaterOrEqual(t, first.Packets, uint64(1))
	require.GreaterOrEqual(t, first.Bytes, uint64(64))
	require.Equal(t, uint32(42), run(0xab000000, 42))
	require.Equal(t, uint32(42), run(8, 42))
	require.Equal(t, first, stats())
	require.NoError(t, objects.Maps["qos_policy"].Update(uint32(7), qosMapPolicy{Ifindex: uint32(lo.Index + 1000), ClassID: 1}, ebpf.UpdateAny))
	require.Equal(t, uint32(42), run(7, 42))
	require.Equal(t, first, stats())
	updatedClassID, err := e.PutQoSPolicy(p)
	require.NoError(t, err)
	require.Equal(t, classID, updatedClassID)
	require.Equal(t, first, stats(), "policy updates preserve counters")
	require.Equal(t, classID, run(7, 42))
	require.Greater(t, stats().Packets, first.Packets)
	require.NoError(t, e.DeleteQoSPolicy(7))
	require.NoError(t, e.DeleteQoSPolicy(7))
	require.Equal(t, uint32(42), run(7, 42))
	var value qosMapPolicy
	require.ErrorIs(t, objects.Maps["qos_policy"].Lookup(uint32(7), &value), ebpf.ErrKeyNotExist)
}
