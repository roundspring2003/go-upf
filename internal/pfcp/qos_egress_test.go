package pfcp

import (
	"testing"

	"github.com/free5gc/go-upf/internal/rules"
	"github.com/free5gc/go-upf/pkg/factory"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
)

func TestQoSPolicyEgressFollowsSourceInterface(t *testing.T) {
	cfg := &factory.QoS{N3Egress: "n3", N6Egress: "n6"}
	d, transport, _ := qosDispatcher(t, cfg)
	// The server captures configuration at startup, not mutable caller memory.
	cfg.N6Egress = "changed"
	s := establishQoSSession(t, d, transport)
	key := rules.PDRKey{SEID: s.LocalID, PDRID: 11}
	p, ok := s.qos.Policy(key)
	require.True(t, ok)
	require.Equal(t, rules.Uplink, p.Direction)
	require.Equal(t, "n6", p.Target.Egress)
	require.Zero(t, p.Target.ClassID)
	require.Empty(t, p.Target.Slice)
	require.Equal(t, rules.MissingTarget, p.Diagnostics[0].Code, "egress alone is not a complete TC class")
	id := p.ID
	modifyQoSSession(t, d, transport, s, ie.NewUpdatePDR(ie.NewPDRID(11),
		ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore))))
	p, _ = s.qos.Policy(key)
	require.Equal(t, id, p.ID)
	require.Equal(t, rules.Downlink, p.Direction)
	require.Equal(t, "n3", p.Target.Egress)
	require.Equal(t, []uint32{7, 9}, p.QERIDs)
	modifyQoSSession(t, d, transport, s, ie.NewUpdateQER(ie.NewQERID(7), ie.NewQFI(6)))
	p, _ = s.qos.Policy(key)
	require.Equal(t, "n3", p.Target.Egress)
	modifyQoSSession(t, d, transport, s, ie.NewUpdatePDR(ie.NewPDRID(11),
		ie.NewPDI(ie.NewSourceInterface(2))))
	p, _ = s.qos.Policy(key)
	require.Equal(t, rules.Unknown, p.Direction)
	require.Nil(t, p.Target)
	require.Equal(t, rules.UnsupportedPath, p.Diagnostics[0].Code)
}
