package pfcp

import (
	"errors"
	"testing"

	"github.com/free5gc/go-upf/internal/forwarder"
	qosmanager "github.com/free5gc/go-upf/internal/qos_manager"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/free5gc/go-upf/pkg/factory"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
)

type recordingEgress struct {
	forwarder.SessionDatapath
	events  []string
	removed []uint32
	fail    bool
}

func (b *recordingEgress) PutQoSPolicy(p rules.Policy) (uint32, error) {
	b.events = append(b.events, "map")
	if b.fail {
		return 0, errors.New("map full")
	}
	return 0xe0010002, nil
}
func (b *recordingEgress) DeleteQoSPolicy(id uint32) error {
	b.events = append(b.events, "delete")
	b.removed = append(b.removed, id)
	return nil
}
func (b *recordingEgress) SetFlowQoS(id uint16, policyID uint32) error {
	b.events = append(b.events, "binding")
	return nil
}
func (b *recordingEgress) ClearFlowQoS(id uint16) error {
	b.events = append(b.events, "clear")
	return nil
}
func TestQoSEgressPublication(t *testing.T) {
	d, transport, _ := qosDispatcher(t, &factory.QoS{N3Egress: "n3", N6Egress: "n6"})
	b := &recordingEgress{}
	d.node.qos = qosmanager.NewManager(qosmanager.NewEgressResolver(
		rules.Target{Egress: "n3"}, rules.Target{Egress: "n6"}), b)
	s := establishQoSSession(t, d, transport)
	b.SessionDatapath = s.datapath
	s.datapath = b
	b.events = nil
	b.removed = nil
	modifyQoSSession(t, d, transport, s, ie.NewUpdateQER(ie.NewQERID(7), ie.NewQFI(6)))
	require.Equal(t, []string{"map", "binding"}, b.events, "QFI may move a policy to another flow class")
	b.events = nil
	b.fail = true
	modifyQoSSession(t, d, transport, s, ie.NewUpdatePDR(ie.NewPDRID(11),
		ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore))))
	require.Equal(t, []string{"map"}, b.events, "do not enable a binding after map publication failed")
	b.fail = false
	b.events = nil
	modifyQoSSession(t, d, transport, s, ie.NewUpdatePDR(ie.NewPDRID(11),
		ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore))))
	require.Equal(t, []string{"map", "binding"}, b.events, "failed TC publication must be retried")
	b.events = nil
	rejectQoSModification(t, d, transport, s, ie.NewUpdateQER(ie.NewQERID(9), ie.NewQFI(5)))
	require.Empty(t, b.events, "rejected QFI change must not touch TC or bindings")
	require.Nil(t, s.QERIDs[9].QFI)
	b.events = nil
	b.removed = nil
	p, ok := s.qos.Policy(rules.PDRKey{SEID: s.LocalID, PDRID: 11})
	require.True(t, ok)
	modifyQoSSession(t, d, transport, s, ie.NewRemovePDR(ie.NewPDRID(11)))
	require.Equal(t, []string{"delete"}, b.events)
	require.Equal(t, []uint32{p.ID}, b.removed)
}
