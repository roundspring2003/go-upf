package pfcp

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	qosmanager "github.com/free5gc/go-upf/internal/qos_manager"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/free5gc/go-upf/pkg/factory"
)

func qosDispatcher(t *testing.T, egress ...*factory.QoS) (*Dispatcher, *messageTransportMock, *logtest.Hook) {
	t.Helper()
	cfg := &factory.Config{
		Pfcp: &factory.Pfcp{Addr: "127.0.0.1", NodeID: "127.0.0.1"},
	}
	if len(egress) > 0 {
		cfg.QoS = egress[0]
	}
	server := NewPfcpServer(cfg, forwarder.Empty{})
	d := server.dispatcher
	log, hook := logtest.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	d.log, d.node.log = logrus.NewEntry(log), logrus.NewEntry(log)
	transport := &messageTransportMock{}
	d.transport = transport
	return d, transport, hook
}

func establishQoSSession(t *testing.T, d *Dispatcher, transport *messageTransportMock) *Session {
	t.Helper()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 8805}
	d.node.EstablishAssociation("127.0.0.2", addr)
	pdr := func(id uint16, qid uint32) *ie.IE {
		return ie.NewCreatePDR(ie.NewPDRID(id), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess)), ie.NewFARID(1),
			ie.NewQERID(qid), ie.NewQERID(9))
	}
	req := message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
		ie.NewNodeID("127.0.0.2", "", ""), ie.NewFSEID(100, addr.IP.To4(), nil),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		pdr(11, 7), pdr(12, 8),
		ie.NewCreateQER(ie.NewQERID(7), ie.NewGateStatus(0, 0), ie.NewQFI(5)),
		ie.NewCreateQER(ie.NewQERID(8), ie.NewGateStatus(0, 0), ie.NewQFI(9)),
		ie.NewCreateQER(ie.NewQERID(9), ie.NewGateStatus(0, 0), ie.NewMBR(60000, 30000)))
	// Exercise decoding and the production dispatcher/parser/validation/apply path.
	buf := make([]byte, req.MarshalLen())
	require.NoError(t, req.MarshalTo(buf))
	decoded, err := message.Parse(buf)
	require.NoError(t, err)
	require.NoError(t, d.HandleRequest(decoded, addr))
	rsp := transport.rsp.(*message.SessionEstablishmentResponse)
	cause, err := rsp.Cause.Cause()
	require.NoError(t, err)
	require.Equal(t, ie.CauseRequestAccepted, cause)
	fseid, err := rsp.UPFSEID.FSEID()
	require.NoError(t, err)
	s, err := d.node.Session(fseid.SEID)
	require.NoError(t, err)
	return s
}

func modifyQoSSession(t *testing.T, d *Dispatcher, transport *messageTransportMock, s *Session, ies ...*ie.IE) {
	t.Helper()
	req := message.NewSessionModificationRequest(0, 0, s.LocalID, 2, 0, ies...)
	require.NoError(t, d.HandleRequest(req, s.association.peerAddr))
	cause, err := transport.rsp.(*message.SessionModificationResponse).Cause.Cause()
	require.NoError(t, err)
	require.Equal(t, ie.CauseRequestAccepted, cause)
}

func rejectQoSModification(t *testing.T, d *Dispatcher, transport *messageTransportMock, s *Session, ies ...*ie.IE) *message.SessionModificationResponse {
	t.Helper()
	req := message.NewSessionModificationRequest(0, 0, s.LocalID, 2, 0, ies...)
	require.NoError(t, d.HandleRequest(req, s.association.peerAddr))
	rsp := transport.rsp.(*message.SessionModificationResponse)
	cause, err := rsp.Cause.Cause()
	require.NoError(t, err)
	require.Equal(t, ie.CauseRuleCreationModificationFailure, cause)
	return rsp
}

func lastAppliedRule(t *testing.T, hook *logtest.Hook, kind string) string {
	t.Helper()
	entries := hook.AllEntries()
	for i := len(entries) - 1; i >= 0; i-- {
		if strings.HasPrefix(entries[i].Message, kind+" applied: ") {
			require.Equal(t, logrus.DebugLevel, entries[i].Level)
			return entries[i].Message
		}
	}
	t.Fatalf("no applied %s log", kind)
	return ""
}

func TestQoSRequestLifecycle(t *testing.T) {
	d, transport, hook := qosDispatcher(t)
	s := establishQoSSession(t, d, transport)
	require.Same(t, d.node.qos, s.qos)
	initial := s.qos.Policies(s.LocalID)
	require.Len(t, initial, 2)
	require.Equal(t, map[uint32]struct{}{7: {}, 9: {}}, s.PDRIDs[11].QERIDs)
	require.Equal(t, uint8(5), *initial[0].QFI)
	require.Equal(t, rules.MissingTarget, initial[0].Diagnostics[0].Code)
	for _, kind := range []string{"PDR", "FAR", "QER"} {
		require.Contains(t, lastAppliedRule(t, hook, kind), "rule=")
	}

	modifyQoSSession(t, d, transport, s, ie.NewUpdateQER(ie.NewQERID(9), ie.NewMBR(70000, 40000)))
	require.Equal(t, initial, s.qos.Policies(s.LocalID), "rate-only updates do not rebuild policies")
	require.Contains(t, lastAppliedRule(t, hook, "QER"), "ID=9")
	require.Contains(t, lastAppliedRule(t, hook, "QER"), "70000000")
	require.Equal(t, uint64(70000000), s.QERIDs[9].MBR.UplinkBps)
	require.Nil(t, s.QERIDs[9].QFI)

	modifyQoSSession(t, d, transport, s, ie.NewUpdateQER(ie.NewQERID(7), ie.NewQFI(6)))
	updated := s.qos.Policies(s.LocalID)
	require.Equal(t, initial[0].ID, updated[0].ID)
	require.Equal(t, uint8(6), *updated[0].QFI)
	require.Equal(t, initial[1], updated[1])

	// Only PDR 11 conflicts: QER 7 has QFI 6, QER 9 requests QFI 9.
	rsp := rejectQoSModification(t, d, transport, s, ie.NewUpdateQER(ie.NewQERID(9), ie.NewQFI(9)))
	require.NotNil(t, rsp.FailedRuleID)
	ruleType, err := rsp.FailedRuleID.RuleIDType()
	require.NoError(t, err)
	require.Equal(t, ie.RuleIDTypePDR, ruleType)
	failedID, err := rsp.FailedRuleID.FailedRuleID()
	require.NoError(t, err)
	require.Equal(t, uint32(11), failedID)
	require.Nil(t, s.QERIDs[9].QFI)
	require.Equal(t, updated, s.qos.Policies(s.LocalID))
	modifyQoSSession(t, d, transport, s, ie.NewUpdatePDR(ie.NewPDRID(12), ie.NewQERID(8)))
	p, ok := s.qos.Policy(rules.PDRKey{SEID: s.LocalID, PDRID: 12})
	require.True(t, ok)
	require.Equal(t, map[uint32]struct{}{8: {}}, s.PDRIDs[12].QERIDs)
	require.Equal(t, uint8(9), *p.QFI)

	modifyQoSSession(t, d, transport, s, ie.NewRemovePDR(ie.NewPDRID(11)))
	require.Len(t, s.qos.Policies(s.LocalID), 1)
	require.Contains(t, s.QERIDs, uint32(9))
	require.NoError(t, d.HandleRequest(message.NewSessionDeletionRequest(0, 0, s.LocalID, 3, 0), s.association.peerAddr))
	cause, err := transport.rsp.(*message.SessionDeletionResponse).Cause.Cause()
	require.NoError(t, err)
	require.Equal(t, ie.CauseRequestAccepted, cause)
	require.Empty(t, s.qos.Policies(s.LocalID))
	replacement := d.node.CreateSession(s.association, 101)
	require.Equal(t, s.LocalID, replacement.LocalID)
	require.Empty(t, replacement.qos.Policies(replacement.LocalID))
}

func TestQoSSynchronizesWithoutDebugLogging(t *testing.T) {
	d, transport, hook := qosDispatcher(t)
	d.log.Logger.SetLevel(logrus.InfoLevel)
	s := establishQoSSession(t, d, transport)
	require.NotNil(t, d.node.qos)
	require.Same(t, d.node.qos, s.qos)
	require.Len(t, s.qos.Policies(s.LocalID), 2)
	modifyQoSSession(t, d, transport, s, ie.NewUpdateQER(ie.NewQERID(7), ie.NewQFI(6)))
	p, ok := s.qos.Policy(rules.PDRKey{SEID: s.LocalID, PDRID: 11})
	require.True(t, ok)
	require.Equal(t, uint8(6), *p.QFI)
	for _, entry := range hook.AllEntries() {
		require.NotContains(t, entry.Message, " applied:")
	}
}

func TestQoSFailedRulesDoNotUpdatePolicies(t *testing.T) {
	d, transport, hook := qosDispatcher(t)
	s := establishQoSSession(t, d, transport)
	original := s.qos.Policies(s.LocalID)
	failure := errors.New("datapath failed")
	backend := &transactionDatapath{apply: func(*rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		return nil, failure
	}}
	s.datapath = backend
	hook.Reset()
	changes, err := s.ParseModificationChanges(&message.SessionModificationRequest{
		UpdateQER: []*ie.IE{ie.NewUpdateQER(ie.NewQERID(7), ie.NewQFI(6))},
	})
	require.NoError(t, err)
	_, err = s.applyRuleChanges(changes, false)
	require.ErrorIs(t, err, failure)
	require.Equal(t, original, s.qos.Policies(s.LocalID))
	require.Equal(t, uint8(5), *s.QERIDs[7].QFI)
	_, err = s.applyRuleChanges(&rules.RuleChangeSet{SEID: s.LocalID, RemoveQERs: []uint32{9}}, false)
	require.Error(t, err)
	require.Equal(t, 1, backend.calls, "reference failure precedes execution")
	require.Empty(t, hook.AllEntries(), "failed operations must not publish QoS events")

	// A policy update error is logged locally, without throwing away rules.
	s.updateQoSPolicies(nil)
	require.Contains(t, hook.LastEntry().Message, "QoS policy update failed")
	require.Equal(t, original, s.qos.Policies(s.LocalID))
	require.Contains(t, s.PDRIDs, uint16(11))
}

func TestQoSConflictRejectedBeforeForwarding(t *testing.T) {
	d, transport, _ := qosDispatcher(t)
	s := establishQoSSession(t, d, transport)
	before := s.qos.Policies(s.LocalID)
	backend := &transactionDatapath{SessionDatapath: s.datapath, apply: func(*rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		t.Fatal("forwarding executed before QFI conflict was rejected")
		return nil, nil
	}}
	s.datapath = backend
	changes, err := s.ParseModificationChanges(&message.SessionModificationRequest{
		UpdateQER: []*ie.IE{ie.NewUpdateQER(ie.NewQERID(9), ie.NewQFI(9))},
	})
	require.NoError(t, err)
	validated, err := s.ValidateRuleState(changes)
	require.Nil(t, validated)
	require.ErrorIs(t, err, qosmanager.ErrAmbiguousQFI)
	require.ErrorIs(t, err, ErrRuleCreationModificationFailed)
	require.Zero(t, backend.calls)
	require.Nil(t, s.QERIDs[9].QFI)
	require.Equal(t, before, s.qos.Policies(s.LocalID))
	_, err = s.applyRuleChanges(changes, false)
	require.ErrorIs(t, err, ErrRuleCreationModificationFailed)
	require.Zero(t, backend.calls)
	require.Nil(t, s.QERIDs[9].QFI)
	require.Equal(t, before, s.qos.Policies(s.LocalID))
}

func TestQoSConflictRejectsSessionEstablishment(t *testing.T) {
	d, transport, _ := qosDispatcher(t)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 8805}
	d.node.EstablishAssociation("127.0.0.2", addr)
	req := message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
		ie.NewNodeID("127.0.0.2", "", ""), ie.NewFSEID(100, addr.IP.To4(), nil),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreatePDR(ie.NewPDRID(11), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess)),
			ie.NewFARID(1), ie.NewQERID(7), ie.NewQERID(9)),
		ie.NewCreateQER(ie.NewQERID(7), ie.NewGateStatus(0, 0), ie.NewQFI(5)),
		ie.NewCreateQER(ie.NewQERID(9), ie.NewGateStatus(0, 0), ie.NewQFI(9)))
	require.NoError(t, d.HandleRequest(req, addr))
	rsp := transport.rsp.(*message.SessionEstablishmentResponse)
	cause, err := rsp.Cause.Cause()
	require.NoError(t, err)
	require.Equal(t, ie.CauseRuleCreationModificationFailure, cause)
	require.NotNil(t, rsp.FailedRuleID)
	failedID, err := rsp.FailedRuleID.FailedRuleID()
	require.NoError(t, err)
	require.Equal(t, uint32(11), failedID)
	require.Empty(t, d.node.qos.Policies(1))
	_, err = d.node.Session(1)
	require.Error(t, err)
}

func TestQoSAssociationCleanupTracksConfirmedRemovals(t *testing.T) {
	d, transport, _ := qosDispatcher(t)
	s := establishQoSSession(t, d, transport)
	original := s.qos.Policies(s.LocalID)
	oldAssociation := s.association
	backend := &cleanupDatapath{SessionDatapath: s.datapath}
	s.datapath = backend
	backend.run = func(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		require.ElementsMatch(t, []uint16{11, 12}, c.RemovePDRs)
		return &forwarder.ApplyResult{Removed: forwarder.RemovedRules{PDRs: []uint16{11}}},
			errors.New("PDR 12 cleanup failed")
	}
	d.node.DeleteAssociation(oldAssociation.PeerNodeID)
	require.True(t, s.closing)
	require.Equal(t, original[1:], s.qos.Policies(s.LocalID), "only confirmed PDR 11 may disappear")
	require.Contains(t, oldAssociation.sessionIDs, s.LocalID)
	require.Empty(t, d.node.sessions.freeSEIDs)

	// A replacement association uses the same manager but a different SEID.
	replacement := establishQoSSession(t, d, transport)
	require.NotEqual(t, s.LocalID, replacement.LocalID)
	require.Same(t, s.qos, replacement.qos)
	other := replacement.qos.Policies(replacement.LocalID)
	require.NotEqual(t, original[0].ID, other[0].ID)
	backend.run = func(*rules.RuleChangeSet) (*forwarder.ApplyResult, error) { return nil, nil }
	d.retrySessionCleanup(s.cleanupRetryAt)
	require.Equal(t, original[1:], s.qos.Policies(s.LocalID), "unconfirmed cleanup must retain policy")
	require.Equal(t, other, s.qos.Policies(replacement.LocalID))

	backend.run = func(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		require.Equal(t, []uint16{12}, c.RemovePDRs)
		return &forwarder.ApplyResult{Removed: forwarder.RemovedRules{
			PDRs: c.RemovePDRs, FARs: c.RemoveFARs, QERs: c.RemoveQERs,
		}}, nil
	}
	d.retrySessionCleanup(s.cleanupRetryAt)
	require.Equal(t, 3, backend.calls)
	require.Empty(t, s.qos.Policies(s.LocalID))
	require.Equal(t, other, s.qos.Policies(replacement.LocalID))
	require.Empty(t, oldAssociation.sessionIDs)
	reused := d.node.CreateSession(replacement.association, 102)
	require.Equal(t, s.LocalID, reused.LocalID)
	require.Empty(t, reused.qos.Policies(reused.LocalID), "reused SEID must not expose old policies")
}
