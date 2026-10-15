package pfcp

import (
	"reflect"
	"slices"
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
			PDRID: 12, PDI: &rules.PDI{SourceInterface: 0}, QERIDs: map[uint32]struct{}{7: {}},
		}}, CreateQERs: []rules.QERConfig{q},
	}
	sess.PDRIDs = make(map[uint16]*rules.PDRConfig)
	sess.QERIDs = make(map[uint32]*rules.QERConfig)
	m := qosmanager.NewManager(nil)
	// No external I/O here. Publish successful rules, then directly update policies.
	apply := func(c *rules.RuleChangeSet) qosmanager.Changes {
		t.Helper()
		state, err := sess.ValidateRuleState(c)
		if err != nil {
			t.Fatal(err)
		}
		state.Commit()
		out, err := m.Apply(sess.LocalID, state)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := apply(creation); len(out.SetBindings) != 2 {
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
	if out := apply(update); len(out.SetBindings) != 2 {
		t.Fatal("QFI users not refreshed", out)
	}
	for _, p := range m.Policies(sess.LocalID) {
		if *p.QFI != 6 {
			t.Fatal(p)
		}
	}
	// Reference validation is owned by the existing PFCP layer.
	for _, c := range []*rules.RuleChangeSet{
		{RemoveQERs: []uint32{7}}, {UpdatePDRs: []rules.PDRPatch{{PDRID: 11, QERIDs: map[uint32]struct{}{99: {}}}}},
		{RemoveFARs: []uint32{1}},
	} {
		if _, err := sess.ValidateRuleState(c); err == nil {
			t.Fatal("dangling reference accepted")
		}
	}
	out := apply(&rules.RuleChangeSet{SEID: sess.LocalID,
		UpdatePDRs: []rules.PDRPatch{{PDRID: 11, QERIDs: map[uint32]struct{}{}}, {PDRID: 12, QERIDs: map[uint32]struct{}{}}},
		RemoveQERs: []uint32{7},
	})
	if len(out.SetBindings) != 2 {
		t.Fatal(out)
	}
	for _, p := range m.Policies(sess.LocalID) {
		if p.QFI != nil || len(p.QFISources) != 0 {
			t.Fatal("stale references", p)
		}
	}
}

func TestRuleStateRangesQoSCandidates(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changes rules.RuleChangeSet
		want    []uint16
		changed []uint16
		removed []uint16
	}{
		{name: "rate-only QER", changes: rules.RuleChangeSet{
			UpdateQERs: []rules.QERPatch{{QERID: 7, MBR: &rules.DirectionalBitRate{UplinkBps: 1000}}},
		}},
		{name: "PDR update", changes: rules.RuleChangeSet{
			UpdatePDRs: []rules.PDRPatch{{PDRID: 11, QERIDs: map[uint32]struct{}{7: {}}}},
		}, want: []uint16{11}, changed: []uint16{11}},
		{name: "PDR removal", changes: rules.RuleChangeSet{
			RemovePDRs: []uint16{12},
		}, removed: []uint16{12}},
		{name: "QFI update", changes: rules.RuleChangeSet{
			UpdateQERs: []rules.QERPatch{{QERID: 7, QFI: statePtr(uint8(6))}},
		}, want: []uint16{11, 12}},
		{name: "PDR and QFI update", changes: rules.RuleChangeSet{
			UpdatePDRs: []rules.PDRPatch{{PDRID: 11, QERIDs: map[uint32]struct{}{7: {}}}},
			UpdateQERs: []rules.QERPatch{{QERID: 7, QFI: statePtr(uint8(6))}},
		}, want: []uint16{11, 12}, changed: []uint16{11}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := newRuleStateTestSession()
			pdr12 := sess.PDRIDs[11].Clone()
			pdr12.PDRID = 12
			sess.PDRIDs[12] = &pdr12
			state, err := sess.ValidateRuleState(&tc.changes)
			if err != nil {
				t.Fatal(err)
			}
			state.Commit()
			var got, changed, removed []uint16
			if err := state.RangeQoSCandidates(func(id uint16, _ *rules.PDRConfig, isChanged bool) error {
				got = append(got, id)
				if isChanged {
					changed = append(changed, id)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := state.RangeRemovedPDR(func(id uint16) error {
				removed = append(removed, id)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			slices.Sort(got)
			slices.Sort(changed)
			if !reflect.DeepEqual(got, tc.want) || !reflect.DeepEqual(changed, tc.changed) ||
				!reflect.DeepEqual(removed, tc.removed) {
				t.Fatal("unexpected candidate/changed/removed PDRs", got, changed, removed)
			}
		})
	}
}
