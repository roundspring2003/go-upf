package pfcp

import (
	"errors"
	"testing"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
)

type recordingBindings struct {
	forwarder.SessionDatapath
	set     map[uint16]uint32
	cleared []uint16
	err     error
}

func (b *recordingBindings) SetFlowQoS(id uint16, policyID uint32) error {
	b.set[id] = policyID
	return b.err
}

func (b *recordingBindings) ClearFlowQoS(id uint16) error {
	b.cleared = append(b.cleared, id)
	return b.err
}

func TestQoSBindingFollowsPolicyChanges(t *testing.T) {
	d, transport, hook := qosDispatcher(t)
	s := establishQoSSession(t, d, transport)
	b := &recordingBindings{SessionDatapath: s.datapath, set: make(map[uint16]uint32)}
	s.datapath = b
	initial := s.qos.Policies(s.LocalID)
	// Exercise the same AddedPolicies publication using the existing complete view.
	s.updateQoSPolicies(&rules.RuleChangeSet{SEID: s.LocalID,
		CreatePDRs: []rules.PDRConfig{*s.PDRIDs[11], *s.PDRIDs[12]},
	}, &RuleState{sess: s})
	require.Equal(t, map[uint16]uint32{11: initial[0].ID, 12: initial[1].ID}, b.set)
	b.set = make(map[uint16]uint32)
	modifyQoSSession(t, d, transport, s, ie.NewUpdateQER(ie.NewQERID(9), ie.NewMBR(70000, 40000)))
	require.Empty(t, b.set, "rate updates retain packet identity")
	modifyQoSSession(t, d, transport, s, ie.NewUpdateQER(ie.NewQERID(7), ie.NewQFI(6)))
	require.Equal(t, map[uint16]uint32{11: initial[0].ID}, b.set)
	modifyQoSSession(t, d, transport, s, ie.NewUpdateQER(ie.NewQERID(9), ie.NewQFI(5)))
	require.ElementsMatch(t, []uint16{11, 12}, b.cleared)
	b.err = errors.New("binding rejected")
	modifyQoSSession(t, d, transport, s, ie.NewUpdatePDR(ie.NewPDRID(12), ie.NewQERID(8)))
	require.Contains(t, hook.LastEntry().Message, "FlowQoS binding update failed")
	require.Contains(t, s.PDRIDs, uint16(12))
	b.err = nil
	b.cleared = nil
	b.set = make(map[uint16]uint32)
	modifyQoSSession(t, d, transport, s, ie.NewRemovePDR(ie.NewPDRID(11)))
	require.Empty(t, b.cleared, "deleted PDR bindings are freed by kernel PDR deletion")
	require.Empty(t, b.set)
}
