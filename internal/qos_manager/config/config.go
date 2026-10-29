// Package config defines the common parameters used by the QoS experiment modes.
package config

import "fmt"

type Mode string

const (
	PerFlowHTB   Mode = "per-flow-htb"
	SharedHTB    Mode = "shared-htb"
	SharedHTBEDT Mode = "shared-htb-edt"
)

// Config applies independently to each egress. This first implementation has
// one local service hierarchy per interface; it does not infer S-NSSAI from QFI.
// All rates are bits/second and all modes use the same FQ leaf parameters.
type Config struct {
	Mode        Mode   `yaml:"mode" valid:"optional"`
	CapacityBps uint64 `yaml:"capacityBps" valid:"optional"`
	GBRBps      uint64 `yaml:"gbrBps" valid:"optional"`
	BEBps       uint64 `yaml:"beBps" valid:"optional"`
	FallbackBps uint64 `yaml:"fallbackBps" valid:"optional"`
	HorizonMS   uint32 `yaml:"horizonMs" valid:"optional"`
	// EgressBudgets are fixed at startup. Experiment preparation may assign
	// different UL (N6) and DL (N3) budgets without runtime rate adjustment.
	EgressBudgets map[string]ClassBudget `yaml:"egressBudgets,omitempty" valid:"optional"`
}

type ClassBudget struct {
	GBRBps      uint64 `yaml:"gbrBps" json:"gbrBps" valid:"optional"`
	BEBps       uint64 `yaml:"beBps" json:"beBps" valid:"optional"`
	FallbackBps uint64 `yaml:"fallbackBps" json:"fallbackBps" valid:"optional"`
}

func (c Config) BudgetFor(egress string) ClassBudget {
	if b, ok := c.EgressBudgets[egress]; ok {
		return b
	}
	return ClassBudget{GBRBps: c.GBRBps, BEBps: c.BEBps, FallbackBps: c.FallbackBps}
}

// ValidateEgresses catches misspelled override names before installing TC.
func (c Config) ValidateEgresses(names []string) error {
	for name := range c.EgressBudgets {
		found := false
		for _, attached := range names {
			found = found || name == attached
		}
		if !found {
			return fmt.Errorf("qos.egressBudgets: %q is not a configured egress", name)
		}
	}
	return nil
}

func (c Config) Normalize() (Config, error) {
	if c.Mode == "" {
		c.Mode = PerFlowHTB
	}
	switch c.Mode {
	case PerFlowHTB, SharedHTB, SharedHTBEDT:
	default:
		return c, fmt.Errorf("unknown qos.mode %q", c.Mode)
	}
	if c.CapacityBps == 0 {
		c.CapacityBps = 1_000_000_000
	}
	if c.GBRBps == 0 && c.BEBps == 0 && c.FallbackBps == 0 {
		c.GBRBps = c.CapacityBps / 2
		c.FallbackBps = c.CapacityBps / 100
		c.BEBps = c.CapacityBps - c.GBRBps - c.FallbackBps
	}
	// Bound rates to keep tc and integer timestamp calculations well-defined.
	if c.CapacityBps < 1000 || c.CapacityBps > 1_000_000_000_000 {
		return c, fmt.Errorf("qos.capacityBps must be between 1000 and 1000000000000")
	}
	if c.GBRBps == 0 || c.BEBps == 0 || c.FallbackBps == 0 ||
		c.GBRBps > c.CapacityBps || c.BEBps > c.CapacityBps || c.FallbackBps > c.CapacityBps ||
		c.GBRBps+c.BEBps+c.FallbackBps != c.CapacityBps {
		return c, fmt.Errorf("positive qos.gbrBps, beBps and fallbackBps must sum to capacityBps")
	}
	budgets := make(map[string]ClassBudget, len(c.EgressBudgets))
	for name, b := range c.EgressBudgets {
		// GBR may be zero in a round without GBR flows in this direction.
		if name == "" || b.BEBps == 0 || b.FallbackBps == 0 ||
			b.GBRBps > c.CapacityBps || b.BEBps > c.CapacityBps || b.FallbackBps > c.CapacityBps ||
			b.GBRBps+b.BEBps+b.FallbackBps != c.CapacityBps {
			return c, fmt.Errorf("qos.egressBudgets[%q]: positive BE/fallback and nonnegative GBR must sum to capacityBps", name)
		}
		budgets[name] = b
	}
	if c.EgressBudgets != nil {
		c.EgressBudgets = budgets
	}
	if c.HorizonMS == 0 {
		c.HorizonMS = 1000
	}
	if c.HorizonMS > 10_000 {
		return c, fmt.Errorf("qos.horizonMs must be at most 10000")
	}
	return c, nil
}
