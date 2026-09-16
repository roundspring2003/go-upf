package qosmanager

import (
	"reflect"
	"slices"
	"testing"

	"github.com/free5gc/go-upf/internal/rules"
)

func ptr[T any](v T) *T { return &v }

type testView struct {
	pdrs                 map[uint16]*rules.PDRConfig
	qers                 map[uint32]*rules.QERConfig
	err                  error
	rangeCalls, qerReads int
}

func (v *testView) PDR(id uint16) (*rules.PDRConfig, bool) { p, ok := v.pdrs[id]; return p, ok }

func (v *testView) QER(id uint32) (*rules.QERConfig, bool) {
	v.qerReads++
	q, ok := v.qers[id]
	return q, ok
}

func (v *testView) RangePDR(visit func(uint16, *rules.PDRConfig) error) error {
	v.rangeCalls++
	if v.err != nil {
		return v.err
	}
	for id, p := range v.pdrs {
		if err := visit(id, p); err != nil {
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
			11: {PDRID: 11, PDI: &rules.PDI{SourceInterface: 0}, QERIDs: []uint32{7, 9}},
			12: {PDRID: 12, PDI: &rules.PDI{SourceInterface: 0}, QERIDs: []uint32{8, 9}},
		},
		qers: map[uint32]*rules.QERConfig{
			7: {QERID: 7, QFI: ptr(uint8(5))}, 8: {QERID: 8, QFI: ptr(uint8(9))},
			9: {QERID: 9, MBR: &rules.DirectionalBitRate{UplinkBps: 60000000}},
		},
	}
}

func translated(t *testing.T, v *testView) rules.Policy {
	t.Helper()
	p, err := translatePolicy(rules.PDRKey{SEID: 10, PDRID: 11}, v, target)
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
	original := translated(t, v)
	v.pdrs[11].QERIDs = []uint32{9, 7, 7}
	p := translated(t, v)
	if !reflect.DeepEqual(original, p) || !reflect.DeepEqual(v.pdrs[11].QERIDs, []uint32{9, 7, 7}) {
		t.Fatal("normalization changed semantics or input")
	}
	*v.qers[7].QFI = 6
	v.pdrs[11].QERIDs[0] = 99
	if *p.QFI != 5 || !reflect.DeepEqual(p.QERIDs, []uint32{7, 9}) {
		t.Fatal("policy aliases rules")
	}
}

func TestPolicyQFISources(t *testing.T) {
	v := fixture()
	v.qers[9].QFI = ptr(uint8(9))
	p := translated(t, v)
	if p.QFI != nil || len(p.QFISources) != 2 || !hasDiagnostic(p, rules.AmbiguousQFI) {
		t.Fatal(p)
	}
	*v.qers[9].QFI = 5
	p = translated(t, v)
	if p.QFI == nil || *p.QFI != 5 || len(p.QFISources) != 2 || len(p.Diagnostics) != 0 {
		t.Fatal(p)
	}
	v.qers[7].QFI, v.qers[9].QFI = nil, nil
	p = translated(t, v)
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
		p := translated(t, v)
		if p.Direction != tc.want || hasDiagnostic(p, rules.UnsupportedPath) != (tc.want == rules.Unknown) {
			t.Fatal(p)
		}
	}
	v.pdrs[11].PDI = &rules.PDI{SourceInterface: 0}
	v.pdrs[11].QERIDs = []uint32{}
	p, err := translatePolicy(rules.PDRKey{SEID: 10, PDRID: 11}, v, nil)
	if err != nil || !hasDiagnostic(p, rules.MissingTarget) || len(p.QERIDs) != 0 || p.Target != nil {
		t.Fatal(p, err)
	}
}

func TestPolicyLostViewAndLargeReferenceSet(t *testing.T) {
	v := fixture()
	delete(v.qers, 9)
	if _, err := translatePolicy(rules.PDRKey{SEID: 10, PDRID: 11}, v, target); err == nil {
		t.Fatal("missing QER accepted")
	}
	delete(v.pdrs, 11)
	if _, err := translatePolicy(rules.PDRKey{SEID: 10, PDRID: 11}, v, target); err == nil {
		t.Fatal("missing PDR accepted")
	}
	v = fixture()
	for id := uint32(100); id < 140; id++ {
		v.qers[id] = &rules.QERConfig{QERID: id}
		v.pdrs[11].QERIDs = append(v.pdrs[11].QERIDs, id)
	}
	if len(translated(t, v).QERIDs) != 42 {
		t.Fatal("references truncated")
	}
}
