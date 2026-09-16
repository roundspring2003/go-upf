package qosmanager

import (
	"errors"
	"reflect"
	"testing"

	"github.com/free5gc/go-upf/internal/rules"
)

func createChanges(seid uint64, v *testView) *rules.RuleChangeSet {
	c := &rules.RuleChangeSet{SEID: seid}
	for _, p := range v.pdrs {
		c.CreatePDRs = append(c.CreatePDRs, p.Clone())
	}
	for _, q := range v.qers {
		c.CreateQERs = append(c.CreateQERs, q.Clone())
	}
	return c
}

func apply(t *testing.T, m *Manager, c *rules.RuleChangeSet, v *testView) Changes {
	t.Helper()
	out, err := m.Apply(c, v, target)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestManagerPDRUpdatesAreLocalAndImmediate(t *testing.T) {
	m, v := NewManager(), fixture()
	out := apply(t, m, createChanges(10, v), v)
	if len(out.AddedPolicies) != 2 || len(m.Policies(10)) != 2 || v.rangeCalls != 0 {
		t.Fatal(out)
	}
	before := m.Policies(10)
	v.pdrs[11].QERIDs = []uint32{7}
	update := &rules.RuleChangeSet{SEID: 10, UpdatePDRs: []rules.PDRPatch{{PDRID: 11, QERIDs: []uint32{7}}}}
	for i := 0; i < 2; i++ { // Equal-value updates still produce operations.
		out = apply(t, m, update, v)
		after := m.Policies(10)
		if !reflect.DeepEqual(out.UpdatedPolicies, []rules.PDRKey{{SEID: 10, PDRID: 11}}) ||
			!reflect.DeepEqual(before[1], after[1]) || before[0].ID != after[0].ID || v.rangeCalls != 0 {
			t.Fatal(out, after)
		}
	}
	delete(v.pdrs, 11)
	out = apply(t, m, &rules.RuleChangeSet{SEID: 10, RemovePDRs: []uint16{11}}, v)
	if len(out.RemovedPolicies) != 1 || !reflect.DeepEqual(m.Policies(10), before[1:]) || v.qers[9] == nil {
		t.Fatal("removal affected another PDR or its QER", out)
	}
}

func TestManagerRateAndGateChangesDoNotRebuildPolicies(t *testing.T) {
	m, v := NewManager(), fixture()
	apply(t, m, createChanges(10, v), v)
	before := m.Policies(10)
	v.rangeCalls, v.qerReads = 0, 0
	v.err = errors.New("unexpected scan")
	v.qers[9].MBR.UplinkBps = 70000000
	for _, c := range []*rules.RuleChangeSet{
		{SEID: 10, UpdateQERs: []rules.QERPatch{{QERID: 9, MBR: v.qers[9].MBR}}},
		{SEID: 10, UpdateQERs: []rules.QERPatch{{QERID: 7, GBR: &rules.DirectionalBitRate{UplinkBps: 1000}}}},
		{SEID: 10, UpdateQERs: []rules.QERPatch{{QERID: 9, GateStatus: &rules.GateStatus{Uplink: 1}}}},
		{SEID: 10, UpdateFARs: []rules.FARPatch{{FARID: 1}}}, {SEID: 10, QueryURRs: []uint32{3}},
		{SEID: 10, CreateQERs: []rules.QERConfig{{QERID: 99}}}, {SEID: 10, RemoveQERs: []uint32{99}}, {SEID: 10},
	} {
		if out := apply(t, m, c, v); !out.Empty() {
			t.Fatal(out)
		}
	}
	if v.rangeCalls != 0 || v.qerReads != 0 || !reflect.DeepEqual(before, m.Policies(10)) {
		t.Fatal("unnecessary work")
	}
}

func TestManagerQFIChangesUseFinalReferences(t *testing.T) {
	m, v := NewManager(), fixture()
	apply(t, m, createChanges(10, v), v)
	before := m.Policies(10)
	v.qers[9].QFI = ptr(uint8(5))
	out := apply(t, m, &rules.RuleChangeSet{SEID: 10, UpdateQERs: []rules.QERPatch{{QERID: 9, QFI: v.qers[9].QFI}}}, v)
	if len(out.UpdatedPolicies) != 2 || !hasDiagnostic(m.Policies(10)[1], rules.AmbiguousQFI) {
		t.Fatal(out)
	}
	delete(v.pdrs, 11)
	v.pdrs[12].QERIDs = []uint32{8}
	v.pdrs[13] = &rules.PDRConfig{PDRID: 13, PDI: &rules.PDI{SourceInterface: 1}, QERIDs: []uint32{9}}
	*v.qers[9].QFI = 6
	out = apply(t, m, &rules.RuleChangeSet{SEID: 10,
		CreatePDRs: []rules.PDRConfig{v.pdrs[13].Clone()}, RemovePDRs: []uint16{11},
		UpdatePDRs: []rules.PDRPatch{{PDRID: 12, QERIDs: []uint32{8}}},
		UpdateQERs: []rules.QERPatch{{QERID: 9, QFI: v.qers[9].QFI}},
	}, v)
	if !reflect.DeepEqual(out.AddedPolicies, []rules.PDRKey{{SEID: 10, PDRID: 13}}) ||
		!reflect.DeepEqual(out.UpdatedPolicies, []rules.PDRKey{{SEID: 10, PDRID: 12}}) ||
		!reflect.DeepEqual(out.RemovedPolicies, []rules.PDRKey{{SEID: 10, PDRID: 11}}) {
		t.Fatal(out)
	}
	after := m.Policies(10)
	if after[0].ID != before[1].ID || *after[0].QFI != 9 || len(after[0].Diagnostics) != 0 ||
		*after[1].QFI != 6 || after[1].Direction != rules.Downlink {
		t.Fatal(after)
	}
}

func TestManagerSessionsInspectionAndCleanup(t *testing.T) {
	m, v := NewManager(), fixture()
	apply(t, m, createChanges(10, v), v)
	apply(t, m, createChanges(20, v), v)
	a, b := m.Policies(10), m.Policies(20)
	if a[0].ID == b[0].ID {
		t.Fatal("ID collision")
	}
	a[0].QERIDs[0] = 999
	*a[0].QFI = 40
	a[0].Target.Egress = "wrong"
	p, ok := m.Policy(rules.PDRKey{SEID: 10, PDRID: 11})
	if !ok || p.QERIDs[0] != 7 || *p.QFI != 5 || p.Target.Egress != "n6" {
		t.Fatal("inspection aliases state")
	}
	p.QERIDs[0] = 999
	if m.Policies(10)[0].QERIDs[0] != 7 {
		t.Fatal("single-policy read aliases state")
	}
	out := m.RemoveSession(10)
	if len(out.RemovedPolicies) != 2 || len(m.Policies(10)) != 0 || !reflect.DeepEqual(b, m.Policies(20)) {
		t.Fatal(out)
	}
	if !m.RemoveSession(10).Empty() {
		t.Fatal("cleanup retry")
	}
	apply(t, m, createChanges(10, v), v)
	if m.Policies(10)[0].ID == p.ID {
		t.Fatal("retired ID reused")
	}
}

func TestManagerErrorsAndIDExhaustion(t *testing.T) {
	m, v := NewManager(), fixture()
	if _, err := m.Apply(nil, v, target); err == nil {
		t.Fatal("nil changes")
	}
	if _, err := m.Apply(createChanges(10, v), nil, target); err == nil {
		t.Fatal("nil view")
	}
	v.err = errors.New("view unavailable")
	_, err := m.Apply(&rules.RuleChangeSet{SEID: 10,
		UpdateQERs: []rules.QERPatch{{QERID: 9, QFI: ptr(uint8(5))}},
	}, v, target)
	if !errors.Is(err, v.err) {
		t.Fatal(err)
	}
	v.err = nil
	m.nextPolicy = uint64(MaxPolicyID)
	if _, err := m.Apply(createChanges(10, v), v, target); !errors.Is(err, ErrIDExhausted) {
		t.Fatal(err)
	}
	if len(m.Policies(10)) != 0 || m.nextPolicy != uint64(MaxPolicyID) {
		t.Fatal("partial apply on error")
	}
	delete(v.pdrs, 12)
	apply(t, m, createChanges(10, v), v)
	if m.Policies(10)[0].ID != MaxPolicyID {
		t.Fatal("last ID lost")
	}
	apply(t, m, &rules.RuleChangeSet{SEID: 10, UpdatePDRs: []rules.PDRPatch{{PDRID: 11}}}, v)
	if _, err := m.Apply(createChanges(20, v), v, target); !errors.Is(err, ErrIDExhausted) {
		t.Fatal("ID wrapped", err)
	}
	m.RemoveSession(10)
}
