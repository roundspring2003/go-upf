// Package qosmanager reconciles policies from validated PFCP state and owns
// the TCX egress program. Manager.Apply also updates its TC policy resources.
package qosmanager

import "github.com/free5gc/go-upf/internal/rules"

// EgressDatapath publishes a policy and returns the classid actually installed
// on its egress interface.
type EgressDatapath interface {
	PutQoSPolicy(rules.Policy) (uint32, error)
	DeleteQoSPolicy(uint32) error
}

// RuleView exposes the validated final QER values and PDR candidates for QoS.
// When QFI, MBR or GBR changes, candidates include unchanged PDRs; the manager determines
// which ones reference the changed QER while reading their QER IDs once.
// The caller serializes the view's lifetime. Reference and field validation
// remain owned by the existing PFCP layer.
type RuleView interface {
	QER(uint32) (*rules.QERConfig, bool)
	QoSUpdated(uint32) bool
	RangeQoSCandidates(func(uint16, *rules.PDRConfig, bool) error) error
	RangeRemovedPDR(func(uint16) error) error
}

type TargetResolver func(rules.PDRKey, rules.Direction) (rules.Target, bool)

func copyPtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
