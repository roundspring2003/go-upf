package forwarder

import (
	"errors"
	"testing"

	"github.com/free5gc/go-gtp5gnl"
	"github.com/khirono/go-nl"
	"github.com/stretchr/testify/require"
)

type bindingTestDriver struct {
	Empty
	oid   gtp5gnl.OID
	attr  nl.Attr
	err   error
	calls int
}

func (d *bindingTestDriver) updateFlowQoS(oid gtp5gnl.OID, attr nl.Attr) error {
	d.oid, d.attr = oid, attr
	d.calls++
	return d.err
}

func TestFlowQoSBindingUsesSessionAndPreservesAppliedRules(t *testing.T) {
	d := &bindingTestDriver{}
	s := NewSessionDatapath(d, 42).(*sessionDatapath)
	s.applied.pdrs[11] = newRuleConfig(gtp5gnl.OID{42, 11}, []nl.Attr{
		{Type: gtp5gnl.PDR_QER_ID, Value: nl.AttrU32(7)},
		{Type: gtp5gnl.PDR_QER_ID, Value: nl.AttrU32(9)},
	})
	require.NoError(t, s.SetFlowQoS(11, 17))
	require.Equal(t, gtp5gnl.OID{42, 11}, d.oid)
	want, err := gtp5gnl.NewFlowQoSAttr(gtp5gnl.FlowQoS{Version: gtp5gnl.FLOW_QOS_BINDING_VERSION, PolicyID: 17, Flags: 1})
	require.NoError(t, err)
	require.Equal(t, want, d.attr)
	require.Len(t, s.applied.pdrs[11].Attrs, 3)
	require.NoError(t, s.SetFlowQoS(11, 17))
	require.Equal(t, 1, d.calls, "confirmed binding should not be sent twice")
	before := newRuleConfig(s.applied.pdrs[11].OID, s.applied.pdrs[11].Attrs)
	d.err = errors.New("netlink failed")
	require.ErrorIs(t, s.SetFlowQoS(11, 18), d.err)
	require.Equal(t, before, s.applied.pdrs[11])
	d.err = nil
	require.NoError(t, s.SetFlowQoS(11, 18))
	require.Equal(t, 3, d.calls, "failed binding should be retried")
	require.NoError(t, s.SetFlowQoS(11, 18))
	require.Equal(t, 3, d.calls)
	require.NoError(t, s.ClearFlowQoS(11))
	clear, err := gtp5gnl.NewFlowQoSAttr(gtp5gnl.FlowQoS{Version: gtp5gnl.FLOW_QOS_BINDING_VERSION})
	require.NoError(t, err)
	require.Equal(t, clear, d.attr)
	require.Equal(t, clear, s.applied.pdrs[11].Attrs[2])
	require.NoError(t, s.ClearFlowQoS(11))
	require.Equal(t, 4, d.calls, "confirmed clear should not be sent twice")
	s.applied.pdrs[12] = newRuleConfig(gtp5gnl.OID{42, 12}, nil)
	require.NoError(t, s.ClearFlowQoS(12))
	require.Equal(t, 4, d.calls, "PDR without a binding is already clear")
	// Binding updates must not create new PDRs or use another session's PDR.
	other := NewSessionDatapath(d, 43).(*sessionDatapath)
	calls := d.calls
	require.Error(t, other.SetFlowQoS(11, 17))
	require.Error(t, s.SetFlowQoS(11, 0))
	require.Error(t, s.SetFlowQoS(11, 0x01000000))
	require.Equal(t, calls, d.calls)
}
