package qosmanager

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/free5gc/go-upf/internal/rules"
)

func ptr[T any](v T) *T { return &v }

type testView struct {
	pdrs                 map[uint16]*rules.PDRConfig
	qers                 map[uint32]*rules.QERConfig
	affected             map[uint16]bool // nil visits all PDRs as changed; false marks an unchanged candidate
	qfiUpdated           map[uint32]bool
	qosUpdated           map[uint32]bool
	removed              []uint16
	err                  error
	rangeCalls, qerReads int
}

func (v *testView) PDR(id uint16) (*rules.PDRConfig, bool) { p, ok := v.pdrs[id]; return p, ok }

func (v *testView) QER(id uint32) (*rules.QERConfig, bool) {
	v.qerReads++
	q, ok := v.qers[id]
	return q, ok
}

func (v *testView) QoSUpdated(id uint32) bool { return v.qfiUpdated[id] || v.qosUpdated[id] }

func (v *testView) RangeQoSCandidates(visit func(uint16, *rules.PDRConfig, bool) error) error {
	v.rangeCalls++
	if v.err != nil {
		return v.err
	}
	for id, p := range v.pdrs {
		changed := true
		if v.affected != nil {
			var candidate bool
			changed, candidate = v.affected[id]
			if !candidate {
				continue
			}
		}
		if err := visit(id, p, changed); err != nil {
			return err
		}
	}
	return nil
}

func (v *testView) RangeRemovedPDR(visit func(uint16) error) error {
	if v.err != nil {
		return v.err
	}
	for _, id := range v.removed {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func target(rules.PDRKey, rules.Direction) (rules.Target, bool) {
	return rules.Target{Egress: "n6", Slice: "slice-1", ClassID: 0x10001}, true
}

func fixture() *testView {
	return &testView{
		pdrs: map[uint16]*rules.PDRConfig{
			11: {PDRID: 11, PDI: &rules.PDI{SourceInterface: 0}, QERIDs: map[uint32]struct{}{7: {}, 9: {}}},
			12: {PDRID: 12, PDI: &rules.PDI{SourceInterface: 0}, QERIDs: map[uint32]struct{}{8: {}, 9: {}}},
		},
		qers: map[uint32]*rules.QERConfig{
			7: {QERID: 7, QFI: ptr(uint8(5))}, 8: {QERID: 8, QFI: ptr(uint8(9))},
			9: {QERID: 9, MBR: &rules.DirectionalBitRate{UplinkBps: 60000000}},
		},
	}
}

func policyFromApply(v *testView, resolver TargetResolver) (rules.Policy, error) {
	m := NewManager(resolver)
	key := rules.PDRKey{SEID: 10, PDRID: 11}
	_, err := m.Apply(10, v)
	if err != nil {
		return rules.Policy{}, err
	}
	p, _ := m.Policy(key)
	return p, nil
}

func appliedPolicy(t *testing.T, v *testView) rules.Policy {
	t.Helper()
	p, err := policyFromApply(v, target)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func hasDiagnostic(p rules.Policy, code string) bool {
	return slices.ContainsFunc(p.Diagnostics, func(d rules.Diagnostic) bool { return d.Code == code })
}

func TestPolicyReferencesAndOwnership(t *testing.T) {
	v := fixture()
	original := appliedPolicy(t, v)
	v.pdrs[11].QERIDs = map[uint32]struct{}{9: {}, 7: {}}
	p := appliedPolicy(t, v)
	if !reflect.DeepEqual(original, p) || !reflect.DeepEqual(v.pdrs[11].QERIDs, map[uint32]struct{}{9: {}, 7: {}}) {
		t.Fatal("policy map changed PDR references")
	}
	*v.qers[7].QFI = 6
	delete(v.pdrs[11].QERIDs, 7)
	v.pdrs[11].QERIDs[99] = struct{}{}
	if *p.QFI != 5 || !reflect.DeepEqual(p.QFISources, map[uint32]uint8{7: 5}) {
		t.Fatal("policy aliases rules")
	}
}

func TestPolicyQFISources(t *testing.T) {
	v := fixture()
	v.qers[8].QFI = ptr(uint8(5))
	v.qers[9].QFI = ptr(uint8(9))
	if _, err := policyFromApply(v, target); !errors.Is(err, ErrAmbiguousQFI) {
		t.Fatal("conflicting QFI accepted", err)
	}
	*v.qers[9].QFI = 5
	p := appliedPolicy(t, v)
	if p.QFI == nil || *p.QFI != 5 || !reflect.DeepEqual(p.QFISources, map[uint32]uint8{7: 5, 9: 5}) || len(p.Diagnostics) != 0 {
		t.Fatal(p)
	}
	v.qers[7].QFI, v.qers[9].QFI = nil, nil
	p = appliedPolicy(t, v)
	if p.QFI != nil || len(p.Diagnostics) != 0 {
		t.Fatal(p)
	}
}

func TestPolicyDirectionAndEmptyReferences(t *testing.T) {
	v := fixture()
	for _, tc := range []struct {
		pdi  *rules.PDI
		want rules.Direction
	}{
		{&rules.PDI{SourceInterface: 0}, rules.Uplink}, {&rules.PDI{SourceInterface: 1}, rules.Downlink},
		{&rules.PDI{SourceInterface: 2}, rules.Unknown}, {nil, rules.Unknown},
	} {
		v.pdrs[11].PDI = tc.pdi
		p := appliedPolicy(t, v)
		if p.Direction != tc.want || hasDiagnostic(p, rules.UnsupportedPath) != (tc.want == rules.Unknown) {
			t.Fatal(p)
		}
	}
	v.pdrs[11].PDI = &rules.PDI{SourceInterface: 0}
	v.pdrs[11].QERIDs = map[uint32]struct{}{}
	p, err := policyFromApply(v, nil)
	if err != nil || !hasDiagnostic(p, rules.MissingTarget) || p.QFI != nil || len(p.QFISources) != 0 || p.Target != nil {
		t.Fatal(p, err)
	}
}

func TestPolicyLostViewAndLargeReferenceSet(t *testing.T) {
	v := fixture()
	delete(v.qers, 9)
	if _, err := policyFromApply(v, target); err == nil {
		t.Fatal("missing QER accepted")
	}
	delete(v.pdrs, 11)
	if _, err := policyFromApply(v, target); err == nil {
		t.Fatal("missing PDR accepted")
	}
	v = fixture()
	for id := uint32(100); id < 140; id++ {
		v.qers[id] = &rules.QERConfig{QERID: id}
		v.pdrs[11].QERIDs[id] = struct{}{}
	}
	v.affected = map[uint16]bool{11: true}
	v.qerReads = 0
	appliedPolicy(t, v)
	if v.qerReads != 42 {
		t.Fatal("QER references were not all read", v.qerReads)
	}
}
