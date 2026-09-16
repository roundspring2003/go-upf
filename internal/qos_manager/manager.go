package qosmanager

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/free5gc/go-upf/internal/rules"
)

const MaxPolicyID uint32 = 0x00ffffff

var ErrIDExhausted = errors.New("QoS policy ID space exhausted")

// Manager stores only current policies and a monotonically increasing packet
// ID. The PFCP event loop is the intended single owner; all access is serialized.
// There is no QER database, constraint graph, pending plan or rollback history.
type Manager struct {
	policies   map[rules.PDRKey]rules.Policy
	nextPolicy uint64
}

func NewManager() *Manager {
	return &Manager{policies: make(map[rules.PDRKey]rules.Policy), nextPolicy: 1}
}

// Apply updates memory immediately using the same RuleChangeSet and complete
// validated view as PFCP. It must be called only for successfully applied rule
// changes, from initial session creation onward. It performs no datapath I/O.
// Target mappings must remain stable outside policies affected by the request.
func (m *Manager) Apply(changes *rules.RuleChangeSet, view RuleView, target TargetResolver) (Changes, error) {
	if changes == nil || view == nil {
		return Changes{}, fmt.Errorf("QoS update requires changes and a validated rule view")
	}
	out, err := policyChanges(changes, view)
	if err != nil {
		return Changes{}, err
	}
	// Finish reads and check capacity before editing current memory. This is
	// local error handling, not a retained plan or an external rollback protocol.
	policies := make([]rules.Policy, 0, len(out.AddedPolicies)+len(out.UpdatedPolicies))
	var needed uint64
	for _, keys := range [][]rules.PDRKey{out.AddedPolicies, out.UpdatedPolicies} {
		for _, key := range keys {
			p, err := translatePolicy(key, view, target)
			if err != nil {
				return Changes{}, err
			}
			p.ID = m.policies[key].ID
			if p.ID == 0 {
				needed++
			}
			policies = append(policies, p)
		}
	}
	if needed > 0 && m.nextPolicy+needed-1 > uint64(MaxPolicyID) {
		return Changes{}, ErrIDExhausted
	}
	for _, key := range out.RemovedPolicies {
		delete(m.policies, key)
	}
	for _, p := range policies {
		if p.ID == 0 {
			p.ID = uint32(m.nextPolicy)
			m.nextPolicy++
		}
		m.policies[p.Key] = p
	}
	return out, nil
}

// RemoveSession removes current policies after all session PDRs are confirmed
// removed. For partial cleanup, Apply only the confirmed RemovePDRs instead.
func (m *Manager) RemoveSession(seid uint64) Changes {
	var out Changes
	for key := range m.policies {
		if key.SEID == seid {
			out.RemovedPolicies = append(out.RemovedPolicies, key)
			delete(m.policies, key)
		}
	}
	slices.SortFunc(out.RemovedPolicies, func(a, b rules.PDRKey) int { return cmp.Compare(a.PDRID, b.PDRID) })
	return out
}

// Policy and Policies return copies for inspection. These are not retained old
// versions; copying only prevents a caller from modifying manager-owned slices.
func (m *Manager) Policy(key rules.PDRKey) (rules.Policy, bool) {
	p, ok := m.policies[key]
	return copyPolicy(p), ok
}

func (m *Manager) Policies(seid uint64) []rules.Policy {
	var out []rules.Policy
	for key, p := range m.policies {
		if key.SEID == seid {
			out = append(out, copyPolicy(p))
		}
	}
	slices.SortFunc(out, func(a, b rules.Policy) int { return cmp.Compare(a.Key.PDRID, b.Key.PDRID) })
	return out
}

func copyPolicy(p rules.Policy) rules.Policy {
	p.QERIDs = slices.Clone(p.QERIDs)
	p.QFISources = slices.Clone(p.QFISources)
	p.Diagnostics = slices.Clone(p.Diagnostics)
	for i := range p.Diagnostics {
		p.Diagnostics[i].QERID = copyPtr(p.Diagnostics[i].QERID)
	}
	p.QFI = copyPtr(p.QFI)
	p.Target = copyPtr(p.Target)
	return p
}
