package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Slice keys use decimal SST and optional six-digit lowercase hex SD, e.g.
// "1-010203". SST-only "1" represents the standard absent SD value 0xffffff.
type SliceBudget struct {
	RateBps uint64 `yaml:"rateBps" valid:"optional"`
	CeilBps uint64 `yaml:"ceilBps" valid:"optional"`
	GBRBps  uint64 `yaml:"gbrBps" valid:"optional"`
	BEBps   uint64 `yaml:"beBps" valid:"optional"`
}
type SliceConfig struct {
	SliceBudget   `yaml:",inline"`
	EgressBudgets map[string]SliceBudget `yaml:"egressBudgets,omitempty" valid:"optional"`
}

func (s SliceConfig) BudgetFor(egress string) SliceBudget {
	if b, ok := s.EgressBudgets[egress]; ok {
		return b
	}
	return s.SliceBudget
}
func validSliceKey(key string) bool {
	parts := strings.Split(key, "-")
	sst, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil || strconv.FormatUint(sst, 10) != parts[0] {
		return false
	}
	if len(parts) == 1 {
		return true
	}
	if len(parts) != 2 || len(parts[1]) != 6 {
		return false
	}
	sd, err := strconv.ParseUint(parts[1], 16, 24)
	return err == nil && sd != 0xffffff && fmt.Sprintf("%06x", sd) == parts[1]
}
func normalizeSliceBudget(b SliceBudget, capacity uint64) (SliceBudget, error) {
	if b.CeilBps == 0 {
		b.CeilBps = b.RateBps
	}
	if b.RateBps == 0 || b.RateBps > b.CeilBps || b.CeilBps > capacity ||
		b.GBRBps > b.RateBps || b.BEBps == 0 || b.BEBps > b.RateBps || b.GBRBps+b.BEBps != b.RateBps {
		return b, fmt.Errorf("slice requires GBR+BE=rate, BE>0 and 0<rate<=ceil<=capacity")
	}
	return b, nil
}
func (c Config) normalizeSlices() (Config, error) {
	if c.CapacityBps < 1000 || c.CapacityBps > 1_000_000_000_000 {
		return c, fmt.Errorf("invalid slice root capacity")
	}
	if c.GBRBps != 0 || c.BEBps != 0 || len(c.EgressBudgets) != 0 {
		return c, fmt.Errorf("qos.slices replaces root gbrBps, beBps and egressBudgets")
	}
	if len(c.Slices) > (65535-16)/3 {
		return c, fmt.Errorf("too many slices for TC class IDs")
	}
	if c.FallbackBps == 0 {
		c.FallbackBps = c.CapacityBps / 100
	}
	if c.FallbackBps > c.CapacityBps {
		return c, fmt.Errorf("fallback exceeds root capacity")
	}
	if c.HorizonMS == 0 {
		c.HorizonMS = 1000
	}
	if c.HorizonMS > 10000 {
		return c, fmt.Errorf("qos.horizonMs must be at most 10000")
	}
	normalized := make(map[string]SliceConfig, len(c.Slices))
	egresses := map[string]bool{"": true}
	for key, s := range c.Slices {
		if !validSliceKey(key) {
			return c, fmt.Errorf("invalid S-NSSAI key %q (use SST or SST-ssssss lowercase hex SD)", key)
		}
		b, err := normalizeSliceBudget(s.SliceBudget, c.CapacityBps)
		if err != nil {
			return c, fmt.Errorf("slice %s: %w", key, err)
		}
		n := SliceConfig{SliceBudget: b}
		if s.EgressBudgets != nil {
			n.EgressBudgets = make(map[string]SliceBudget, len(s.EgressBudgets))
		}
		for iface, b := range s.EgressBudgets {
			if iface == "" {
				return c, fmt.Errorf("empty slice egress name")
			}
			b, err = normalizeSliceBudget(b, c.CapacityBps)
			if err != nil {
				return c, fmt.Errorf("slice %s egress %s: %w", key, iface, err)
			}
			n.EgressBudgets[iface] = b
			egresses[iface] = true
		}
		normalized[key] = n
	}
	c.Slices = normalized
	for iface := range egresses {
		total := c.FallbackBps
		for _, s := range c.Slices {
			b := s.BudgetFor(iface)
			if b.RateBps > c.CapacityBps-total {
				return c, fmt.Errorf("slice reservations plus fallback exceed capacity on egress %q", iface)
			}
			total += b.RateBps
		}
	}
	return c, nil
}
