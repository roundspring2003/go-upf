package qosmanager

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/free5gc/go-upf/internal/qos_manager/tc"
	"github.com/free5gc/go-upf/internal/rules"
)

const MaxPolicyID uint32 = 0x00ffffff

var ErrIDExhausted = errors.New("QoS policy ID space exhausted")
var ErrAmbiguousQFI = errors.New("PDR references QERs with different QFI values")

type AmbiguousQFIError struct{ PDRID uint16 }

func (e *AmbiguousQFIError) Error() string {
	return fmt.Sprintf("PDR %d: %s", e.PDRID, ErrAmbiguousQFI)
}
func (e *AmbiguousQFIError) Unwrap() error { return ErrAmbiguousQFI }

// Manager owns its target resolver, current policies, packet IDs, and optional
// TC egress resources. The PFCP event loop serializes policy access.
// There is no QER database, constraint graph or rollback history.
type Manager struct {
	policies   map[rules.PDRKey]rules.Policy
	nextPolicy uint64
	target     TargetResolver
	egress     EgressDatapath
	closeTC    func() error
}

// NewManager captures the deployment resolver once. A nil resolver leaves
// targets unresolved; callers must keep the resolver's mapping stable. The
// optional egress dependency is useful for tests; OpenManager owns production TC.
func NewManager(target TargetResolver, egress ...EgressDatapath) *Manager {
	m := &Manager{policies: make(map[rules.PDRKey]rules.Policy), nextPolicy: 1, target: target}
	if len(egress) != 0 {
		m.egress = egress[0]
	}
	return m
}

// OpenManager owns the TC resources and the policy resolver for this UPF.
func OpenManager(n3, n6 string) (*Manager, error) {
	egress, err := tc.OpenTCEgress([]string{n3, n6})
	if err != nil {
		return nil, err
	}
	m := NewManager(NewEgressResolver(
		rules.Target{Egress: n3}, rules.Target{Egress: n6}), egress)
	m.closeTC = egress.Close
	return m, nil
}

func (m *Manager) Close() error {
	if m.closeTC == nil {
		return nil
	}
	closeTC := m.closeTC
	m.closeTC = nil
	return closeTC()
}

// Prepared holds a QoS calculation until forwarding succeeds.
// The PFCP event loop must serialize Prepare and ApplyPrepared with other
// manager operations. Discard this value if forwarding fails.
type Prepared struct {
	manager  *Manager
	policies []rules.Policy
	removed  []rules.PDRKey
	used     bool
}

// Prepare derives affected policies without changing manager memory or TC.
// Each candidate PDR's QER IDs are traversed once. Conflicting QFI values
// reject the whole request before forwarding rules are applied.
func (m *Manager) Prepare(seid uint64, view RuleView) (*Prepared, error) {
	if view == nil {
		return nil, fmt.Errorf("QoS update requires a validated rule view")
	}
	// Read and validate all affected PDRs before changing memory or TC.
	var policies []rules.Policy
	var needed uint64
	err := view.RangeQoSCandidates(func(id uint16, pdr *rules.PDRConfig, changed bool) error {
		if pdr == nil {
			return fmt.Errorf("validated rule view lost PDR %d", id)
		}
		key := rules.PDRKey{SEID: seid, PDRID: id}
		p := rules.Policy{Key: key}
		conflictingQFI := false
		for qerID := range pdr.QERIDs {
			if view.QFIUpdated(qerID) {
				changed = true
			}
			qer, ok := view.QER(qerID)
			if !ok || qer == nil {
				return fmt.Errorf("validated rule view lost QER %d referenced by PDR %d", qerID, id)
			}
			if qer.QFI != nil {
				if p.QFISources == nil {
					p.QFISources = make(map[uint32]uint8)
				}
				p.QFISources[qerID] = *qer.QFI
				if p.QFI == nil {
					p.QFI = copyPtr(qer.QFI)
				} else if *p.QFI != *qer.QFI {
					conflictingQFI = true
				}
			}
		}
		if !changed {
			return nil
		}
		if conflictingQFI {
			return &AmbiguousQFIError{PDRID: id}
		}
		p.Direction = resolveDirection(pdr)
		addDiagnostic := func(code, detail string) {
			p.Diagnostics = append(p.Diagnostics, rules.Diagnostic{Code: code, PDR: key, Detail: detail})
		}
		if p.Direction == rules.Unknown {
			addDiagnostic(rules.UnsupportedPath, "PDR Source Interface does not resolve a supported direction")
		} else {
			var target rules.Target
			var found bool
			if m.target != nil {
				target, found = m.target(key, p.Direction)
			}
			if found && target.Egress != "" {
				p.Target = &target
			}
			if p.Target == nil || target.ClassID == 0 {
				addDiagnostic(rules.MissingTarget, "egress or installed TC class is unavailable")
			}
		}
		p.ID = m.policies[key].ID
		if p.ID == 0 {
			needed++
		}
		policies = append(policies, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	plan := &Prepared{manager: m, policies: policies}
	err = view.RangeRemovedPDR(func(id uint16) error {
		key := rules.PDRKey{SEID: seid, PDRID: id}
		if _, exists := m.policies[key]; exists {
			plan.removed = append(plan.removed, key)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if needed > 0 && m.nextPolicy+needed-1 > uint64(MaxPolicyID) {
		return nil, ErrIDExhausted
	}
	//this is to ensure that the order of policies and removed policies is consistent for testing and debugging
	slices.SortFunc(plan.policies, func(a, b rules.Policy) int { return cmp.Compare(a.Key.PDRID, b.Key.PDRID) })
	slices.SortFunc(plan.removed, func(a, b rules.PDRKey) int { return cmp.Compare(a.PDRID, b.PDRID) })
	return plan, nil
}

// ApplyPrepared publishes a previously validated calculation after forwarding
// succeeds. TC successes are returned as binding updates; TC failures are
// omitted from those updates and returned as errors.
func (m *Manager) ApplyPrepared(plan *Prepared) (Changes, error) {
	if plan == nil || plan.manager != m || plan.used {
		return Changes{}, fmt.Errorf("invalid or already applied QoS preparation")
	}
	plan.used = true
	out := Changes{RemovedPolicies: plan.removed}
	var errs []error
	for _, key := range out.RemovedPolicies {
		id := m.policies[key].ID
		delete(m.policies, key)
		if m.egress != nil {
			if err := m.egress.DeleteQoSPolicy(id); err != nil {
				errs = append(errs, fmt.Errorf("delete TC policy %d: %w", id, err))
			}
		}
	}
	for _, p := range plan.policies {
		old, exists := m.policies[p.Key]
		valid := bindablePolicy(p)
		// A changed PDR can still yield the same QoS policy.
		if exists && samePolicy(old, p) {
			continue
		}
		if p.ID == 0 {
			p.ID = uint32(m.nextPolicy)
			m.nextPolicy++
		}
		m.policies[p.Key] = p
		if m.egress != nil {
			if valid {
				classID, err := m.egress.PutQoSPolicy(p)
				if err != nil {
					errs = append(errs, fmt.Errorf("publish TC policy %d for PDR %d: %w", p.ID, p.Key.PDRID, err))
					continue
				}
				if classID == 0 || p.Target == nil {
					errs = append(errs, fmt.Errorf("TC policy %d for PDR %d returned no class", p.ID, p.Key.PDRID))
					continue
				}
				p.Target.ClassID = classID
				p.Diagnostics = slices.DeleteFunc(p.Diagnostics, func(d rules.Diagnostic) bool {
					return d.Code == rules.MissingTarget
				})
				m.policies[p.Key] = p
			} else if err := m.egress.DeleteQoSPolicy(p.ID); err != nil {
				errs = append(errs, fmt.Errorf("delete TC policy %d for PDR %d: %w", p.ID, p.Key.PDRID, err))
				continue
			}
		}
		if valid {
			out.SetBindings = append(out.SetBindings, p.Key)
		} else {
			out.ClearBindings = append(out.ClearBindings, p.Key)
		}
	}
	return out, errors.Join(errs...)
}

// Apply is a convenience for callers that already applied forwarding rules.
// PFCP uses Prepare before forwarding and ApplyPrepared only after success.
func (m *Manager) Apply(seid uint64, view RuleView) (Changes, error) {
	plan, err := m.Prepare(seid, view)
	if err != nil {
		return Changes{}, err
	}
	return m.ApplyPrepared(plan)
}

func samePolicy(a, b rules.Policy) bool {
	if a.Key != b.Key || a.ID != b.ID || a.Direction != b.Direction ||
		!maps.Equal(a.QFISources, b.QFISources) ||
		!samePtr(a.QFI, b.QFI) {
		return false
	}
	if (a.Target == nil) != (b.Target == nil) {
		return false
	}
	if a.Target != nil && (a.Target.Egress != b.Target.Egress || a.Target.Slice != b.Target.Slice) {
		return false
	}
	// ClassID is assigned by TC after publication; MissingTarget is cleared then.
	withoutClassDiagnostic := func(ds []rules.Diagnostic) []rules.Diagnostic {
		return slices.DeleteFunc(slices.Clone(ds), func(d rules.Diagnostic) bool { return d.Code == rules.MissingTarget })
	}
	return slices.EqualFunc(withoutClassDiagnostic(a.Diagnostics), withoutClassDiagnostic(b.Diagnostics),
		func(x, y rules.Diagnostic) bool {
			return x.Code == y.Code && x.PDR == y.PDR && x.Detail == y.Detail && samePtr(x.QERID, y.QERID)
		})
}

func samePtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func bindablePolicy(p rules.Policy) bool {
	return p.Direction == rules.Uplink || p.Direction == rules.Downlink
}

// RemoveConfirmedPDRs handles partial datapath cleanup. The remaining PFCP
// rules may be temporarily inconsistent, so only confirmed removals are used.
func (m *Manager) RemoveConfirmedPDRs(seid uint64, ids []uint16) error {
	var errs []error
	for _, id := range ids {
		key := rules.PDRKey{SEID: seid, PDRID: id}
		p, ok := m.policies[key]
		if !ok {
			continue
		}
		delete(m.policies, key)
		if m.egress != nil {
			if err := m.egress.DeleteQoSPolicy(p.ID); err != nil {
				errs = append(errs, fmt.Errorf("delete TC policy %d: %w", p.ID, err))
			}
		}
	}
	return errors.Join(errs...)
}

// RemoveSession removes current policies after all session PDRs are confirmed
// removed. Partial cleanup uses RemoveConfirmedPDRs for confirmed deletions.
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
// versions; copying prevents callers from modifying manager-owned values.
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
	p.QFISources = maps.Clone(p.QFISources)
	p.Diagnostics = slices.Clone(p.Diagnostics)
	for i := range p.Diagnostics {
		p.Diagnostics[i].QERID = copyPtr(p.Diagnostics[i].QERID)
	}
	p.QFI = copyPtr(p.QFI)
	p.Target = copyPtr(p.Target)
	return p
}
