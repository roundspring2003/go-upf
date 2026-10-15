package qosmanager

import "github.com/free5gc/go-upf/internal/rules"

// Changes reports removed policies and PDR bindings ready after TC updates.
type Changes struct {
	RemovedPolicies []rules.PDRKey
	SetBindings     []rules.PDRKey
	ClearBindings   []rules.PDRKey
}

func (c Changes) Empty() bool {
	return len(c.RemovedPolicies)+len(c.SetBindings)+len(c.ClearBindings) == 0
}
