package qosmanager

import (
	"cmp"
	"slices"

	"github.com/free5gc/go-upf/internal/rules"
)

// Changes reports policy operations performed by Apply. QER operations already
// exist in RuleChangeSet and remain available to the existing/future backend.
type Changes struct {
	AddedPolicies   []rules.PDRKey
	UpdatedPolicies []rules.PDRKey
	RemovedPolicies []rules.PDRKey
}

func (c Changes) Empty() bool {
	return len(c.AddedPolicies)+len(c.UpdatedPolicies)+len(c.RemovedPolicies) == 0
}

// policyChanges reuses explicit PFCP operations, without graph comparisons or
// a reverse reference database. A PDR edit affects that policy only. A QFI patch
// also refreshes policies referring to the QER, since they store a QFI summary.
// MBR/GBR/gate updates do not affect any data stored in a policy.
func policyChanges(changes *rules.RuleChangeSet, view RuleView) (Changes, error) {
	var out Changes
	added := make(map[uint16]bool)
	updated := make(map[uint16]bool)
	key := func(id uint16) rules.PDRKey { return rules.PDRKey{SEID: changes.SEID, PDRID: id} }
	for _, p := range changes.CreatePDRs {
		added[p.PDRID] = true
	}
	for _, p := range changes.UpdatePDRs {
		updated[p.PDRID] = true
	}
	for _, id := range changes.RemovePDRs {
		out.RemovedPolicies = append(out.RemovedPolicies, key(id))
	}
	qfiUpdates := make(map[uint32]bool)
	for _, q := range changes.UpdateQERs {
		if q.QFI != nil {
			qfiUpdates[q.QERID] = true
		}
	}
	if len(qfiUpdates) > 0 {
		err := view.RangePDR(func(id uint16, p *rules.PDRConfig) error {
			for _, qid := range p.QERIDs {
				if qfiUpdates[qid] {
					updated[id] = true
					break
				}
			}
			return nil
		})
		if err != nil {
			return Changes{}, err
		}
	}
	for id := range added {
		out.AddedPolicies = append(out.AddedPolicies, key(id))
	}
	for id := range updated {
		if !added[id] {
			out.UpdatedPolicies = append(out.UpdatedPolicies, key(id))
		}
	}
	for _, keys := range [][]rules.PDRKey{out.AddedPolicies, out.UpdatedPolicies, out.RemovedPolicies} {
		slices.SortFunc(keys, func(a, b rules.PDRKey) int { return cmp.Compare(a.PDRID, b.PDRID) })
	}
	return out, nil
}
