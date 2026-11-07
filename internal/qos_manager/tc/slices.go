package tc

import (
	"fmt"
	"sort"

	qosconfig "github.com/free5gc/go-upf/internal/qos_manager/config"
	"github.com/free5gc/go-upf/internal/rules"
)

type sliceClasses struct {
	parent, gbr, be uint16
	budget          qosconfig.SliceBudget
}

func (m *classManager) openSlices(iface string) error {
	if err := m.htb("add", iface, fallbackMinor, 1, m.cfg.FallbackBps, m.cfg.CapacityBps, 2); err != nil {
		return err
	}
	if err := m.fq(iface, fallbackMinor); err != nil {
		return err
	}
	keys := make([]string, 0, len(m.cfg.Slices))
	for key := range m.cfg.Slices {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for i, key := range keys {
		parent := uint16(16 + 3*i)
		b := m.cfg.Slices[key].BudgetFor(iface)
		group := sliceClasses{parent: parent, gbr: parent + 1, be: parent + 2, budget: b}
		m.groups[iface][key] = group
		for _, id := range []uint16{parent, parent + 1, parent + 2} {
			m.used[iface][id] = true
		}
		if err := m.htb("add", iface, parent, 1, b.RateBps, b.CeilBps, 0); err != nil {
			return err
		}
		for _, service := range []struct {
			minor uint16
			rate  uint64
			gbr   bool
			prio  int
		}{
			{group.gbr, b.GBRBps, true, 0}, {group.be, b.BEBps, false, 1},
		} {
			if service.rate == 0 {
				continue
			}
			if err := m.htb("add", iface, service.minor, parent, service.rate, b.CeilBps, service.prio); err != nil {
				return err
			}
			if !m.cfg.Mode.PerFlowClass(service.gbr) {
				if err := m.fq(iface, service.minor); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (m *classManager) serviceFor(p rules.Policy) (minor uint16, budget, ceiling uint64, err error) {
	if p.Target == nil {
		return 0, 0, 0, fmt.Errorf("policy has no egress target")
	}
	group, ok := m.groups[p.Target.Egress][p.Target.Slice]
	if !ok {
		return 0, 0, 0, fmt.Errorf("unknown or missing S-NSSAI %q on egress %s", p.Target.Slice, p.Target.Egress)
	}
	if p.GBR() > 0 {
		return group.gbr, group.budget.GBRBps, group.budget.CeilBps, nil
	}
	return group.be, group.budget.BEBps, group.budget.CeilBps, nil
}

// validateChanges simulates the publication order, including removals, without
// changing TC or live reservations. Only touched flows and their members are
// copied. This also rejects a temporary over-admission during a multi-PDR update,
// even if its final total would fit (send decreases before increases instead).
func (m *classManager) validateChanges(policies []rules.Policy, removed []rules.PDRKey) error {
	type serviceKey struct {
		iface  string
		parent uint16
	}
	type projectedFlow struct {
		members  map[rules.PDRKey]rules.Policy
		rate     uint64
		service  serviceKey
		capacity uint64
	}
	changed := make(map[flowKey]*projectedFlow)
	totals := make(map[serviceKey]uint64)
	assignments := make(map[rules.PDRKey]*flowKey)
	total := func(sk serviceKey) uint64 {
		if v, ok := totals[sk]; ok {
			return v
		}
		return m.totals[sk.iface][sk.parent]
	}
	touch := func(key flowKey) *projectedFlow {
		if f := changed[key]; f != nil {
			return f
		}
		group := m.groups[key.iface][key.slice]
		parent := group.be
		if key.service == 2 {
			parent = group.gbr
		}
		f := &projectedFlow{members: make(map[rules.PDRKey]rules.Policy), service: serviceKey{key.iface, parent}, capacity: group.budget.CeilBps}
		if old := m.flows[key]; old != nil {
			f.rate = old.rate
			for _, p := range old.members {
				f.members[p.Key] = p
			}
		}
		changed[key] = f
		return f
	}
	lookup := func(key rules.PDRKey) *flowKey {
		if k, ok := assignments[key]; ok {
			return k
		}
		if id, ok := m.byKey[key]; ok {
			a := m.active[id]
			if a.dedicated {
				k := a.flow
				return &k
			}
		}
		return nil
	}
	rates := func(f *projectedFlow, incoming *rules.Policy) (uint64, uint64) {
		members := make(map[uint32]rules.Policy, len(f.members)+1)
		var i uint32
		for key, p := range f.members {
			if incoming != nil && key == incoming.Key {
				continue
			}
			members[i] = p
			i++
		}
		if incoming != nil {
			members[i] = *incoming
		}
		if len(members) == 0 {
			return 0, 0
		}
		return flowRates(members, f.capacity)
	}
	setRate := func(f *projectedFlow, rate uint64) {
		totals[f.service] = total(f.service) - f.rate + rate
		f.rate = rate
	}
	remove := func(key rules.PDRKey) {
		if old := lookup(key); old != nil {
			f := touch(*old)
			delete(f.members, key)
			rate, _ := rates(f, nil)
			setRate(f, rate)
		}
		assignments[key] = nil
	}
	for _, key := range removed {
		remove(key)
	}
	for _, p := range policies {
		if p.Target == nil {
			remove(p.Key)
			continue
		}
		_, budget, _, err := m.serviceFor(p)
		if err != nil {
			return err
		}
		if p.GBR() > budget {
			return fmt.Errorf("PDR %d GBR exceeds slice/service budget", p.Key.PDRID)
		}
		if !m.cfg.Mode.PerFlowClass(p.GBR() > 0) {
			remove(p.Key)
			continue
		}
		key := keyFor(p)
		f := touch(key)
		rate, ceil := rates(f, &p)
		if rate > ceil {
			return fmt.Errorf("flow GBR exceeds MBR or slice ceiling")
		}
		projected := total(f.service) - f.rate
		old := lookup(p.Key)
		if old != nil && *old != key {
			other := touch(*old)
			// Match Prepare: the old flow is still present until publication;
			// only a sole member moving within this service releases its budget.
			if other.service == f.service && len(other.members) == 1 {
				projected -= other.rate
			}
		}
		if projected+rate > budget {
			return fmt.Errorf("flow rates exceed slice/service budget during publication on %s class e001:%x", f.service.iface, f.service.parent)
		}
		if old != nil && *old != key {
			remove(p.Key)
		}
		f.members[p.Key] = p
		setRate(f, rate)
		assignments[p.Key] = &key
	}
	return nil
}
