package qosmanager

import (
	"fmt"
	"slices"

	"github.com/free5gc/go-upf/internal/rules"
)

// translatePolicy reads an already validated, merged PDR and its QERs. It copies
// only policy metadata; it never stores QER configs or recalculates rates/gates.
func translatePolicy(key rules.PDRKey, view RuleView, target TargetResolver) (rules.Policy, error) {
	p, ok := view.PDR(key.PDRID)
	if !ok || p == nil {
		return rules.Policy{}, fmt.Errorf("validated rule view lost PDR %d", key.PDRID)
	}
	policy := rules.Policy{Key: key, Direction: resolveDirection(p)}
	add := func(code, detail string) {
		policy.Diagnostics = append(policy.Diagnostics, rules.Diagnostic{Code: code, PDR: key, Detail: detail})
	}
	if policy.Direction == rules.Unknown {
		add(rules.UnsupportedPath, "PDR Source Interface does not resolve a supported direction")
	} else {
		var t rules.Target
		var found bool
		if target != nil {
			t, found = target(key, policy.Direction)
		}
		if found && t.Egress != "" {
			policy.Target = &t
		}
		if policy.Target == nil || t.Slice == "" || t.ClassID == 0 {
			add(rules.MissingTarget, "explicit egress, slice and class mapping is required")
		}
	}
	policy.QERIDs = slices.Clone(p.QERIDs)
	slices.Sort(policy.QERIDs)
	policy.QERIDs = slices.Compact(policy.QERIDs)
	qfiValues := make(map[uint8]bool)
	for _, id := range policy.QERIDs {
		q, ok := view.QER(id)
		if !ok || q == nil {
			return rules.Policy{}, fmt.Errorf("validated rule view lost QER %d referenced by PDR %d", id, key.PDRID)
		}
		if q.QFI != nil {
			policy.QFISources = append(policy.QFISources, rules.QFISource{QERID: id, QFI: *q.QFI})
			qfiValues[*q.QFI] = true
		}
	}
	if len(qfiValues) > 1 {
		add(rules.AmbiguousQFI, "referenced QERs contain different QFI values")
	} else {
		for qfi := range qfiValues {
			policy.QFI = copyPtr(&qfi)
		}
	}
	return policy, nil
}
