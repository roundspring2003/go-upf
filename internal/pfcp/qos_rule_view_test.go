package pfcp

import (
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	qosmanager "github.com/free5gc/go-upf/internal/qos_manager"
	"github.com/free5gc/go-upf/internal/rules"
)

var _ qosmanager.RuleView = (*RuleState)(nil)

func TestQoSManagerUsesExistingRules(t *testing.T) {
	sess := newRuleStateTestSession()
	sess.PDRIDs[11].PDI = &rules.PDI{SourceInterface: 0}
	// FAR is still validated by PFCP, but does not override Source Interface.
	sess.FARIDs[1].ForwardingParameters = &rules.ForwardingParameters{DestinationInterface: statePtr(uint8(0))}
	q, err := parseCreateQER(ie.NewCreateQER(ie.NewQERID(7),
		ie.NewGateStatus(ie.GateStatusClosed, ie.GateStatusOpen), ie.NewMBR(60000, 30000),
		ie.NewGBR(10000, 5000), ie.NewQFI(5)))
	if err != nil {
		t.Fatal(err)
	}
	creation := &rules.RuleChangeSet{SEID: sess.LocalID,
		CreatePDRs: []rules.PDRConfig{sess.PDRIDs[11].Clone(), {
			PDRID: 12, PDI: &rules.PDI{SourceInterface: 0}, QERIDs: []uint32{7},
		}}, CreateQERs: []rules.QERConfig{q},
	}
	sess.PDRIDs = make(map[uint16]*rules.PDRConfig)
	sess.QERIDs = make(map[uint32]*rules.QERConfig)
	m := qosmanager.NewManager()
	// No external I/O here. Publish successful rules, then directly update policies.
	apply := func(c *rules.RuleChangeSet) qosmanager.Changes {
		t.Helper()
		state, err := sess.ValidateRuleState(c)
		if err != nil {
			t.Fatal(err)
		}
		state.Commit()
		out, err := m.Apply(c, state, nil)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := apply(creation); len(out.AddedPolicies) != 2 {
		t.Fatal(out)
	}
	p := m.Policies(sess.LocalID)[0]
	if p.Direction != rules.Uplink || p.QFI == nil || *p.QFI != 5 {
		t.Fatal(p)
	}
	update, err := sess.ParseModificationChanges(&message.SessionModificationRequest{
		UpdateQER: []*ie.IE{ie.NewUpdateQER(ie.NewQERID(7), ie.NewMBR(70000, 40000))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out := apply(update); !out.Empty() {
		t.Fatal("MBR update rewrote policies", out)
	}
	got := sess.QERIDs[7]
	if got.MBR.UplinkBps != 70000000 || got.GBR.DownlinkBps != 5000000 || *got.QFI != 5 ||
		got.GateStatus.Uplink != ie.GateStatusClosed || got.GateStatus.Downlink != ie.GateStatusOpen {
		t.Fatal("existing parser/merge result changed", got)
	}
	update, err = sess.ParseModificationChanges(&message.SessionModificationRequest{
		UpdateQER: []*ie.IE{ie.NewUpdateQER(ie.NewQERID(7), ie.NewQFI(6))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out := apply(update); len(out.UpdatedPolicies) != 2 {
		t.Fatal("QFI users not refreshed", out)
	}
	for _, p := range m.Policies(sess.LocalID) {
		if *p.QFI != 6 {
			t.Fatal(p)
		}
	}
	// Reference validation is owned by the existing PFCP layer.
	for _, c := range []*rules.RuleChangeSet{
		{RemoveQERs: []uint32{7}}, {UpdatePDRs: []rules.PDRPatch{{PDRID: 11, QERIDs: []uint32{99}}}},
		{RemoveFARs: []uint32{1}},
	} {
		if _, err := sess.ValidateRuleState(c); err == nil {
			t.Fatal("dangling reference accepted")
		}
	}
	out := apply(&rules.RuleChangeSet{SEID: sess.LocalID,
		UpdatePDRs: []rules.PDRPatch{{PDRID: 11, QERIDs: []uint32{}}, {PDRID: 12, QERIDs: []uint32{}}},
		RemoveQERs: []uint32{7},
	})
	if len(out.UpdatedPolicies) != 2 {
		t.Fatal(out)
	}
	for _, p := range m.Policies(sess.LocalID) {
		if len(p.QERIDs) != 0 || p.QFI != nil || len(p.QFISources) != 0 {
			t.Fatal("stale references", p)
		}
	}
}
