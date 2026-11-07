package pfcp

import (
	"errors"
	"github.com/free5gc/go-upf/internal/forwarder"
	"os"
	"testing"

	qosmanager "github.com/free5gc/go-upf/internal/qos_manager"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/free5gc/go-upf/pkg/factory"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type sliceEgress struct {
	recordingEgress
	published []rules.Policy
}

func (*sliceEgress) UsesSlices() bool { return true }
func (b *sliceEgress) PutQoSPolicy(p rules.Policy) (uint32, error) {
	b.published = append(b.published, p)
	return b.recordingEgress.PutQoSPolicy(p)
}
func TestSessionSliceBinding(t *testing.T) {
	d, transport, _ := qosDispatcher(t, &factory.QoS{N3Egress: "n3", N6Egress: "n6"})
	b := &sliceEgress{}
	d.node.qos = qosmanager.NewManager(qosmanager.NewEgressResolver(rules.Target{Egress: "n3"}, rules.Target{Egress: "n6"}), b)
	s := establishQoSSession(t, d, transport, ie.NewSNSSAI(1, 0x010203))
	require.Equal(t, "1-010203", s.SNSSAI)
	require.Len(t, b.published, 2)
	for _, p := range b.published {
		require.Equal(t, "1-010203", p.Target.Slice)
	}
	b.published = nil
	modifyQoSSession(t, d, transport, s, ie.NewUpdateQER(ie.NewQERID(7), ie.NewQFI(6)))
	require.NotEmpty(t, b.published)
	require.Equal(t, "1-010203", b.published[0].Target.Slice)
	b.published = nil
	rejectQoSModification(t, d, transport, s, ie.NewSNSSAI(1, 0x112233))
	require.Empty(t, b.published)
	require.Equal(t, "1-010203", s.SNSSAI)
	modifyQoSSession(t, d, transport, s, ie.NewSNSSAI(1, 0x010203))
}
func TestSliceCandidateDoesNotMutateSession(t *testing.T) {
	s := &Session{LocalID: 10}
	key := "1-010203"
	state, err := s.ValidateRuleState(&rules.RuleChangeSet{SEID: 10, SNSSAI: &key})
	require.NoError(t, err)
	require.Equal(t, "", s.SNSSAI)
	require.Equal(t, key, state.QoSSlice())
	state.Commit()
	require.Equal(t, key, s.SNSSAI)
	state, err = s.ValidateRuleState(&rules.RuleChangeSet{SEID: 10})
	require.NoError(t, err)
	require.Equal(t, key, state.QoSSlice())
}
func TestParseSlice(t *testing.T) {
	p, err := parseSessionSlice(ie.NewSNSSAI(1, 0xffffff))
	require.NoError(t, err)
	require.Equal(t, "1", *p)
	p, err = parseSessionSlice(nil)
	require.NoError(t, err)
	require.Nil(t, p)
	_, err = parseSessionSlice(ie.New(ie.SNSSAI, []byte{1, 2, 3}))
	require.Error(t, err)
}
func TestSMFSliceWireFixture(t *testing.T) {
	path := os.Getenv("FLOWQOS_SLICE_WIRE_FIXTURE")
	if path == "" {
		t.Skip("set path to the SMF encoder fixture")
	}
	wire, err := os.ReadFile(path)
	require.NoError(t, err)
	decoded, err := message.Parse(wire)
	require.NoError(t, err)
	req, ok := decoded.(*message.SessionEstablishmentRequest)
	require.True(t, ok)
	key, err := parseSessionSlice(req.SNSSAI)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "1-010203", *key)
}

func TestSliceIdentitySurvivesRuleRemoval(t *testing.T) {
	s := &Session{LocalID: 10, SNSSAI: "1-010203"}
	other := "1-112233"
	_, err := s.ValidateRuleState(&rules.RuleChangeSet{SEID: 10, SNSSAI: &other})
	require.Error(t, err, "removing all PDRs does not authorize moving the session to a different slice")
}
func TestSliceNotCommittedOnDatapathFailure(t *testing.T) {
	failed := errors.New("datapath failure")
	s := &Session{LocalID: 10, datapath: &transactionDatapath{apply: func(*rules.RuleChangeSet) (*forwarder.ApplyResult, error) { return nil, failed }}}
	key := "1-010203"
	_, err := s.applyRuleChanges(&rules.RuleChangeSet{SEID: 10, SNSSAI: &key}, true)
	require.ErrorIs(t, err, failed)
	require.Empty(t, s.SNSSAI)
}
func TestUnslicedBackendAcceptsSessionSlice(t *testing.T) {
	d, transport, _ := qosDispatcher(t, &factory.QoS{N3Egress: "n3", N6Egress: "n6"})
	b := &recordingEgress{}
	d.node.qos = qosmanager.NewManager(qosmanager.NewEgressResolver(rules.Target{Egress: "n3"}, rules.Target{Egress: "n6"}), b)
	s := establishQoSSession(t, d, transport, ie.NewSNSSAI(1, 0x010203))
	require.Equal(t, "1-010203", s.SNSSAI)
	for _, p := range s.qos.Policies(s.LocalID) {
		require.Empty(t, p.Target.Slice, "legacy TC hierarchy remains unsliced")
	}
}
