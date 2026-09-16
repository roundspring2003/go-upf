// Package qosmanager updates local policies using existing PFCP rule changes.
// It does not own PFCP rules, classify packets or perform datapath I/O.
package qosmanager

import "github.com/free5gc/go-upf/internal/rules"

// RuleView must expose a complete candidate after PFCP parsing and
// Session.ValidateRuleState have succeeded. The caller serializes its lifetime.
// Reference and field validation remain owned by the existing PFCP layer.
type RuleView interface {
	PDR(uint16) (*rules.PDRConfig, bool)
	QER(uint32) (*rules.QERConfig, bool)
	RangePDR(func(uint16, *rules.PDRConfig) error) error
}

type TargetResolver func(rules.PDRKey, rules.Direction) (rules.Target, bool)

func copyPtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
