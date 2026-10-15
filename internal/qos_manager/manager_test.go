package qosmanager

import (
	"errors"
	"reflect"
	"testing"

	"github.com/free5gc/go-upf/internal/rules"
)

func apply(t *testing.T, m *Manager, seid uint64, v *testView) Changes {
	t.Helper()
	out, err := m.Apply(seid, v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestManagerReconcilesFinalPDRState(t *testing.T) {
	m, v := NewManager(target), fixture()
	out := apply(t, m, 10, v)
	if len(out.SetBindings) != 2 || len(m.Policies(10)) != 2 || v.rangeCalls != 1 {
		t.Fatal(out)
	}
	before := m.Policies(10)
	v.pdrs[11].QERIDs = map[uint32]struct{}{7: {}}
	if out = apply(t, m, 10, v); !out.Empty() || !reflect.DeepEqual(before, m.Policies(10)) {
		t.Fatal("QER reference without QFI changed policy", out)
	}
	v.pdrs[11].PDI.SourceInterface = 1
	out = apply(t, m, 10, v)
	after := m.Policies(10)
	if !reflect.DeepEqual(out.SetBindings, []rules.PDRKey{{SEID: 10, PDRID: 11}}) ||
		!reflect.DeepEqual(before[1], after[1]) || before[0].ID != after[0].ID || after[0].Direction != rules.Downlink {
		t.Fatal(out, after)
	}
	if out = apply(t, m, 10, v); !out.Empty() {
		t.Fatal("unchanged final state rewrote a policy", out)
	}
	delete(v.pdrs, 11)
	v.removed = []uint16{11}
	out = apply(t, m, 10, v)
	if !reflect.DeepEqual(out.RemovedPolicies, []rules.PDRKey{{SEID: 10, PDRID: 11}}) ||
		!reflect.DeepEqual(m.Policies(10), before[1:]) || v.qers[9] == nil {
		t.Fatal("removal affected another PDR or its QER", out)
	}
}

func TestManagerReadsOnlyAffectedPDRs(t *testing.T) {
	m, v := NewManager(target), fixture()
	apply(t, m, 10, v)
	before, _ := m.Policy(rules.PDRKey{SEID: 10, PDRID: 12})
	v.affected = map[uint16]bool{11: true}
	v.pdrs[11].PDI.SourceInterface = 1
	delete(v.qers, 8) // Unchanged PDR 12 would fail if the manager read it.
	out := apply(t, m, 10, v)
	if !reflect.DeepEqual(out.SetBindings, []rules.PDRKey{{SEID: 10, PDRID: 11}}) {
		t.Fatal(out)
	}
	after, _ := m.Policy(rules.PDRKey{SEID: 10, PDRID: 12})
	if !reflect.DeepEqual(before, after) {
		t.Fatal("unaffected policy changed", after)
	}
}

func TestManagerQERReferenceWithoutQFIDoesNotRewriteTC(t *testing.T) {
	egress := &managerEgressRecorder{}
	m := NewManager(NewEgressResolver(rules.Target{Egress: "n3"}, rules.Target{Egress: "n6"}), egress)
	v := fixture()
	apply(t, m, 10, v)
	before := m.Policies(10)
	v.affected = map[uint16]bool{11: true}
	v.qers[10] = &rules.QERConfig{QERID: 10}
	v.pdrs[11].QERIDs = map[uint32]struct{}{7: {}, 10: {}}
	v.qerReads = 0
	if out := apply(t, m, 10, v); !out.Empty() || len(egress.puts) != 2 || v.qerReads != 2 ||
		!reflect.DeepEqual(before, m.Policies(10)) {
		t.Fatal("QER reference without QFI rewrote TC policy", out, egress, v.qerReads)
	}
}

func TestManagerRateAndGateChangesDoNotRebuildPolicies(t *testing.T) {
	egress := &managerEgressRecorder{}
	m := NewManager(NewEgressResolver(rules.Target{Egress: "n3"}, rules.Target{Egress: "n6"}), egress)
	v := fixture()
	apply(t, m, 10, v)
	before := m.Policies(10)
	v.rangeCalls, v.qerReads = 0, 0
	v.affected = map[uint16]bool{}
	v.qers[9].MBR.UplinkBps = 70000000
	v.qers[7].GBR = &rules.DirectionalBitRate{UplinkBps: 1000}
	v.qers[9].GateStatus = &rules.GateStatus{Uplink: 1}
	if out := apply(t, m, 10, v); !out.Empty() {
		t.Fatal(out)
	}
	if v.rangeCalls != 1 || v.qerReads != 0 || len(egress.puts) != 2 ||
		!reflect.DeepEqual(before, m.Policies(10)) {
		t.Fatal("rate-only change read QERs or rewrote TC or binding")
	}
}

func TestManagerQFIChangesUseFinalReferences(t *testing.T) {
	m, v := NewManager(target), fixture()
	apply(t, m, 10, v)
	before := m.Policies(10)
	v.qers[9].QFI = ptr(uint8(5))
	if _, err := m.Apply(10, v); !errors.Is(err, ErrAmbiguousQFI) || !reflect.DeepEqual(before, m.Policies(10)) {
		t.Fatal("conflict changed manager state", err, m.Policies(10))
	}
	delete(v.pdrs, 11)
	v.removed = []uint16{11}
	v.pdrs[12].QERIDs = map[uint32]struct{}{8: {}}
	v.pdrs[13] = &rules.PDRConfig{PDRID: 13, PDI: &rules.PDI{SourceInterface: 1}, QERIDs: map[uint32]struct{}{9: {}}}
	*v.qers[9].QFI = 6
	out := apply(t, m, 10, v)
	if !reflect.DeepEqual(out.SetBindings, []rules.PDRKey{{SEID: 10, PDRID: 13}}) ||
		!reflect.DeepEqual(out.RemovedPolicies, []rules.PDRKey{{SEID: 10, PDRID: 11}}) {
		t.Fatal(out)
	}
	after := m.Policies(10)
	if after[0].ID != before[1].ID || *after[0].QFI != 9 || len(after[0].Diagnostics) != 0 ||
		*after[1].QFI != 6 || after[1].Direction != rules.Downlink {
		t.Fatal(after)
	}
}

func TestManagerQFIUpdateScansEachCandidateReferencesOnce(t *testing.T) {
	m, v := NewManager(target), fixture()
	v.qers[8].QFI = ptr(uint8(5))
	v.pdrs[13] = &rules.PDRConfig{PDRID: 13, PDI: &rules.PDI{SourceInterface: 0}, QERIDs: map[uint32]struct{}{10: {}}}
	v.qers[10] = &rules.QERConfig{QERID: 10}
	apply(t, m, 10, v)
	before, _ := m.Policy(rules.PDRKey{SEID: 10, PDRID: 13})

	v.affected = map[uint16]bool{11: false, 12: false, 13: false}
	v.qfiUpdated = map[uint32]bool{9: true}
	v.qers[9].QFI = ptr(uint8(5))
	v.qerReads = 0
	out := apply(t, m, 10, v)
	if v.qerReads != 5 {
		t.Fatalf("expected one QER lookup for each candidate reference, got %d", v.qerReads)
	}
	if !reflect.DeepEqual(out.SetBindings, []rules.PDRKey{{SEID: 10, PDRID: 11}, {SEID: 10, PDRID: 12}}) ||
		len(out.ClearBindings) != 0 {
		t.Fatal("QFI update did not select only its referencing PDRs", out)
	}
	after, _ := m.Policy(rules.PDRKey{SEID: 10, PDRID: 13})
	if !reflect.DeepEqual(before, after) {
		t.Fatal("unrelated candidate policy changed", after)
	}
}

func TestManagerPrepareDoesNotPublishAndUsesComputedPolicyOnce(t *testing.T) {
	egress := &managerEgressRecorder{}
	m, v := NewManager(target, egress), fixture()
	plan, err := m.Prepare(10, v)
	if err != nil || len(m.Policies(10)) != 0 || len(egress.puts) != 0 || v.qerReads != 4 {
		t.Fatal("Prepare changed manager or TC state", err, egress, v.qerReads)
	}
	out, err := m.ApplyPrepared(plan)
	if err != nil || len(out.SetBindings) != 2 || len(egress.puts) != 2 || v.qerReads != 4 {
		t.Fatal("ApplyPrepared reread QERs or failed to publish", err, out, egress, v.qerReads)
	}
	if _, err := m.ApplyPrepared(plan); err == nil {
		t.Fatal("prepared update was applied twice")
	}
}

func TestManagerSessionsInspectionAndCleanup(t *testing.T) {
	m, v := NewManager(target), fixture()
	apply(t, m, 10, v)
	apply(t, m, 20, v)
	a, b := m.Policies(10), m.Policies(20)
	if a[0].ID == b[0].ID {
		t.Fatal("ID collision")
	}
	a[0].QFISources[7] = 99
	*a[0].QFI = 40
	a[0].Target.Egress = "wrong"
	p, ok := m.Policy(rules.PDRKey{SEID: 10, PDRID: 11})
	if !ok || p.QFISources[7] != 5 || *p.QFI != 5 || p.Target.Egress != "n6" {
		t.Fatal("inspection aliases state")
	}
	p.QFISources[7] = 42
	stored := m.Policies(10)[0]
	if stored.QFISources[7] != 5 {
		t.Fatal("single-policy read aliases state")
	}
	out := m.RemoveSession(10)
	if len(out.RemovedPolicies) != 2 || len(m.Policies(10)) != 0 || !reflect.DeepEqual(b, m.Policies(20)) {
		t.Fatal(out)
	}
	if !m.RemoveSession(10).Empty() {
		t.Fatal("cleanup retry")
	}
	apply(t, m, 10, v)
	if m.Policies(10)[0].ID == p.ID {
		t.Fatal("retired ID reused")
	}
}

func TestManagerErrorsAndIDExhaustion(t *testing.T) {
	m, v := NewManager(target), fixture()
	if _, err := m.Apply(10, nil); err == nil {
		t.Fatal("nil view")
	}
	v.err = errors.New("view unavailable")
	if _, err := m.Apply(10, v); !errors.Is(err, v.err) {
		t.Fatal(err)
	}
	v.err = nil
	m.nextPolicy = uint64(MaxPolicyID)
	if _, err := m.Apply(10, v); !errors.Is(err, ErrIDExhausted) {
		t.Fatal(err)
	}
	if len(m.Policies(10)) != 0 || m.nextPolicy != uint64(MaxPolicyID) {
		t.Fatal("partial apply on error")
	}
	delete(v.pdrs, 12)
	apply(t, m, 10, v)
	if m.Policies(10)[0].ID != MaxPolicyID {
		t.Fatal("last ID lost")
	}
	apply(t, m, 10, v)
	if _, err := m.Apply(20, v); !errors.Is(err, ErrIDExhausted) {
		t.Fatal("ID wrapped", err)
	}
	m.RemoveSession(10)
}

func TestManagerApplyViewErrorDoesNotPublishPartialPolicies(t *testing.T) {
	m, v := NewManager(target), fixture()
	apply(t, m, 10, v)
	before := m.Policies(10)
	v.pdrs[11].QERIDs = map[uint32]struct{}{7: {}}
	delete(v.qers, 8)
	_, err := m.Apply(10, v)
	if err == nil || !reflect.DeepEqual(before, m.Policies(10)) {
		t.Fatal("view error changed manager state", err, m.Policies(10))
	}
}

type managerEgressRecorder struct {
	puts         []uint32
	deletes      []uint32
	failPutID    uint32
	failDeleteID uint32
}

func (e *managerEgressRecorder) PutQoSPolicy(p rules.Policy) (uint32, error) {
	e.puts = append(e.puts, p.ID)
	if p.ID == e.failPutID {
		return 0, errors.New("TC map update failed")
	}
	return 0xe0010002, nil
}

func (e *managerEgressRecorder) DeleteQoSPolicy(id uint32) error {
	e.deletes = append(e.deletes, id)
	if id == e.failDeleteID {
		return errors.New("TC class deletion failed")
	}
	return nil
}

func TestManagerApplyPublishesTCAndReportsBindingOutcomes(t *testing.T) {
	egress := &managerEgressRecorder{}
	m := NewManager(NewEgressResolver(rules.Target{Egress: "n3"}, rules.Target{Egress: "n6"}), egress)
	v := fixture()
	out := apply(t, m, 10, v)
	if !reflect.DeepEqual(egress.puts, []uint32{1, 2}) || len(out.SetBindings) != 2 || len(out.ClearBindings) != 0 {
		t.Fatal("Apply did not publish TC before reporting bindings", egress, out)
	}
	key11 := rules.PDRKey{SEID: 10, PDRID: 11}
	p11, _ := m.Policy(key11)
	if p11.Target.ClassID != 0xe0010002 || hasDiagnostic(p11, rules.MissingTarget) {
		t.Fatal("installed class was not recorded", p11)
	}

	egress.failPutID = p11.ID
	v.pdrs[11].PDI.SourceInterface = 1
	v.pdrs[12].PDI.SourceInterface = 1
	out, err := m.Apply(10, v)
	if err == nil || !reflect.DeepEqual(out.SetBindings, []rules.PDRKey{{SEID: 10, PDRID: 12}}) ||
		len(out.ClearBindings) != 0 || !reflect.DeepEqual(egress.puts, []uint32{1, 2, 1, 2}) {
		t.Fatal("failed TC publication enabled a binding or blocked another PDR", err, out, egress)
	}
	p11, _ = m.Policy(key11)
	if p11.Target.ClassID != 0 || !hasDiagnostic(p11, rules.MissingTarget) {
		t.Fatal("failed publication retained a new class assignment", p11)
	}

	delete(v.pdrs, 11)
	v.removed = []uint16{11}
	out = apply(t, m, 10, v)
	if !reflect.DeepEqual(egress.deletes, []uint32{p11.ID}) ||
		!reflect.DeepEqual(out.RemovedPolicies, []rules.PDRKey{key11}) {
		t.Fatal("Apply did not delete the removed PDR's TC policy", egress, out)
	}
}

func TestManagerApplySkipsClearBindingWhenTCDeleteFails(t *testing.T) {
	egress := &managerEgressRecorder{}
	m := NewManager(NewEgressResolver(rules.Target{Egress: "n3"}, rules.Target{Egress: "n6"}), egress)
	v := fixture()
	apply(t, m, 10, v)
	egress.failDeleteID = 1
	v.pdrs[11].PDI.SourceInterface = 2
	out, err := m.Apply(10, v)
	if err == nil || len(out.ClearBindings) != 0 || !reflect.DeepEqual(egress.deletes, []uint32{1}) {
		t.Fatal("failed TC deletion cleared the PDR binding", err, out, egress)
	}
}

func TestRemoveConfirmedPDRsWithIncompleteCleanupView(t *testing.T) {
	m, v := NewManager(target), fixture()
	apply(t, m, 10, v)
	delete(v.pdrs, 11)
	delete(v.qers, 9) // PDR 12 still references QER 9 during partial cleanup.
	if err := m.RemoveConfirmedPDRs(10, []uint16{11}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Policy(rules.PDRKey{SEID: 10, PDRID: 11}); ok || len(m.Policies(10)) != 1 {
		t.Fatal("confirmed PDR was not removed without scanning the incomplete view")
	}
}
