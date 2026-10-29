package tc

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	qosconfig "github.com/free5gc/go-upf/internal/qos_manager/config"
	"github.com/free5gc/go-upf/internal/rules"
)

const qdiscMajor uint32 = 0xe0010000
const fallbackMinor uint16 = 4
const firstFlowMinor uint16 = 16

type tcRunner func(...string) error

func runTC(args ...string) error {
	out, err := exec.Command("tc", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

type flowKey struct {
	iface     string
	seid      uint64
	direction rules.Direction
	qfi       uint8
	pdr       uint16 // Used only when the PDR has no QFI.
	hasQFI    bool
	service   uint16
}

func keyFor(p rules.Policy) flowKey {
	k := flowKey{iface: p.Target.Egress, seid: p.Key.SEID, direction: p.Direction, service: serviceMinor(p)}
	if p.QFI != nil {
		k.qfi, k.hasQFI = *p.QFI, true
	} else {
		k.pdr = p.Key.PDRID
	}
	return k
}

type classAssignment struct {
	iface string
	minor uint16
	flow  flowKey
}

func (a classAssignment) id() uint32 { return qdiscMajor | uint32(a.minor) }

type flowClass struct {
	assignment classAssignment
	members    map[uint32]rules.Policy
	rate, ceil uint64
	parent     uint16
}

type classUpdate struct {
	assignment       classAssignment
	policy           rules.Policy
	created          bool
	oldRate, oldCeil uint64
}

type classManager struct {
	run     tcRunner
	cfg     qosconfig.Config
	roots   []string
	active  map[uint32]classAssignment
	pending map[uint32]classUpdate
	flows   map[flowKey]*flowClass
	used    map[string]map[uint16]bool
	stale   []classAssignment
	totals  map[string]map[uint16]uint64
	dirty   map[flowKey]bool
}

func openClasses(names []string, run tcRunner, options ...qosconfig.Config) (*classManager, error) {
	var cfg qosconfig.Config
	if len(options) > 0 {
		cfg = options[0]
	}
	cfg, err := cfg.Normalize()
	if err != nil {
		return nil, err
	}
	if err := cfg.ValidateEgresses(names); err != nil {
		return nil, err
	}
	m := &classManager{totals: make(map[string]map[uint16]uint64), dirty: make(map[flowKey]bool), run: run, cfg: cfg, active: make(map[uint32]classAssignment), pending: make(map[uint32]classUpdate), flows: make(map[flowKey]*flowClass), used: make(map[string]map[uint16]bool)}
	for _, name := range names {
		budget := cfg.BudgetFor(name)
		if err := run("qdisc", "add", "dev", name, "root", "handle", "e001:", "htb", "default", "4"); err != nil {
			return nil, errors.Join(err, m.Close())
		}
		m.roots = append(m.roots, name)
		m.used[name] = map[uint16]bool{1: true, 2: true, 3: true, 4: true}
		m.totals[name] = make(map[uint16]uint64)
		if err := m.htb("add", name, 1, 0, cfg.CapacityBps, cfg.CapacityBps, 0); err != nil {
			return nil, errors.Join(err, m.Close())
		}
		for _, group := range []struct {
			minor uint16
			rate  uint64
			prio  int
		}{{2, budget.GBRBps, 0}, {3, budget.BEBps, 1}, {4, budget.FallbackBps, 2}} {
			if group.rate == 0 {
				continue // No GBR traffic planned on this egress for this round.
			}
			if err := m.htb("add", name, group.minor, 1, group.rate, cfg.CapacityBps, group.prio); err != nil {
				return nil, errors.Join(err, m.Close())
			}
			if cfg.Mode != qosconfig.PerFlowHTB || group.minor == fallbackMinor {
				if err := m.fq(name, group.minor); err != nil {
					return nil, errors.Join(err, m.Close())
				}
			}
		}
	}
	return m, nil
}

func (m *classManager) htb(operation, iface string, minor, parent uint16, rate, ceil uint64, prio int) error {
	parentID := "e001:"
	if parent != 0 {
		parentID = fmt.Sprintf("e001:%x", parent)
	}
	return m.run("class", operation, "dev", iface, "parent", parentID, "classid", fmt.Sprintf("e001:%x", minor), "htb", "rate", fmt.Sprintf("%dbit", rate), "ceil", fmt.Sprintf("%dbit", ceil), "prio", fmt.Sprint(prio), "quantum", "1514")
}
func (m *classManager) fq(iface string, minor uint16) error {
	return m.run("qdisc", "add", "dev", iface, "parent", fmt.Sprintf("e001:%x", minor), "fq", "limit", "10000", "flow_limit", "1000", "horizon", fmt.Sprintf("%dms", m.cfg.HorizonMS), "horizon_drop")
}
func (m *classManager) Close() error {
	var errs []error
	for i := len(m.roots) - 1; i >= 0; i-- {
		if err := m.run("qdisc", "del", "dev", m.roots[i], "root", "handle", "e001:"); err != nil {
			errs = append(errs, err)
		}
	}
	m.roots = nil
	return errors.Join(errs...)
}
func serviceMinor(p rules.Policy) uint16 {
	if p.GBR() > 0 {
		return 2
	}
	return 3
}

// Prepare publishes no policy map. Commit transfers membership only after BPF
// publication succeeds. Shared classes live until Close, not until a PDR ends.
func (m *classManager) Prepare(p rules.Policy) (uint32, bool, error) {
	if _, ok := m.pending[p.ID]; ok {
		return 0, false, fmt.Errorf("unfinished class update for policy %d", p.ID)
	}
	iface := p.Target.Egress
	if _, ok := m.used[iface]; !ok {
		return 0, false, fmt.Errorf("TC egress %s is not attached", iface)
	}
	if p.Target.Slice != "" {
		return 0, false, fmt.Errorf("TC modes currently support one local hierarchy, not slice %q", p.Target.Slice)
	}
	budget := m.cfg.BudgetFor(iface)
	if p.GBR() > budget.GBRBps {
		return 0, false, fmt.Errorf("flow GBR exceeds fixed service budget on %s", iface)
	}
	a := classAssignment{iface: iface, minor: serviceMinor(p)}
	if m.cfg.Mode != qosconfig.PerFlowHTB {
		m.pending[p.ID] = classUpdate{assignment: a, policy: p}
		return a.id(), false, nil
	}
	k := keyFor(p)
	a.flow = k
	f := m.flows[k]
	members := map[uint32]rules.Policy{p.ID: p}
	if f != nil {
		for id, member := range f.members {
			if id != p.ID {
				members[id] = member
			}
		}
	}
	rate, ceil := flowRates(members, m.cfg.CapacityBps)
	if rate > ceil {
		return 0, false, fmt.Errorf("flow GBR exceeds its MBR/capacity")
	}
	// Avoid claiming guarantees after over-admission. Shared modes intentionally
	// do not make a per-flow guarantee; their class budget is fixed.
	total := m.totals[iface][serviceMinor(p)]
	if f != nil {
		total -= f.rate
	}
	if old, ok := m.active[p.ID]; ok && old.flow != k && old.iface == iface {
		if other := m.flows[old.flow]; other != nil && other.parent == serviceMinor(p) && len(other.members) == 1 {
			total -= other.rate
		}
	}
	serviceBudget := budget.BEBps
	if p.GBR() > 0 {
		serviceBudget = budget.GBRBps
	}
	if total+rate > serviceBudget {
		return 0, false, fmt.Errorf("flow rates exceed service budget on %s", iface)
	}
	update := classUpdate{policy: p}
	if f != nil {
		a = f.assignment
		update.oldRate, update.oldCeil = f.rate, f.ceil
		if rate != f.rate || ceil != f.ceil {
			if err := m.htb("change", iface, a.minor, f.parent, rate, ceil, 0); err != nil {
				return 0, false, err
			}
		}
	} else {
		for minor := uint32(firstFlowMinor); minor < 0xffff; minor++ {
			if !m.used[iface][uint16(minor)] {
				a.minor = uint16(minor)
				break
			}
		}
		if a.minor < firstFlowMinor {
			return 0, false, fmt.Errorf("TC class IDs exhausted on %s", iface)
		}
		if err := m.htb("add", iface, a.minor, serviceMinor(p), rate, ceil, 0); err != nil {
			return 0, false, err
		}
		m.used[iface][a.minor] = true
		if err := m.fq(iface, a.minor); err != nil {
			return 0, false, errors.Join(err, m.deleteClass(a))
		}
		update.created = true
	}
	update.assignment = a
	m.pending[p.ID] = update
	return a.id(), update.created, nil
}
func (m *classManager) Rollback(id uint32, _ bool) error {
	u, ok := m.pending[id]
	if !ok {
		return nil
	}
	var err error
	if u.created {
		err = m.deleteClass(u.assignment)
	} else if u.oldRate != 0 {
		err = m.htb("change", u.assignment.iface, u.assignment.minor, serviceMinor(u.policy), u.oldRate, u.oldCeil, 0)
	}
	if err == nil {
		delete(m.pending, id)
	}
	return err
}
func (m *classManager) Commit(id uint32) {
	u, ok := m.pending[id]
	if !ok {
		return
	}
	if old, exists := m.active[id]; exists && old != u.assignment {
		m.release(id, old)
	}
	m.active[id] = u.assignment
	if m.cfg.Mode == qosconfig.PerFlowHTB {
		f := m.flows[u.assignment.flow]
		if f == nil {
			f = &flowClass{assignment: u.assignment, members: make(map[uint32]rules.Policy), parent: serviceMinor(u.policy)}
			m.flows[u.assignment.flow] = f
		}
		f.members[id] = u.policy
		m.totals[f.assignment.iface][f.parent] -= f.rate
		f.rate, f.ceil = flowRates(f.members, m.cfg.CapacityBps)
		m.totals[f.assignment.iface][f.parent] += f.rate
		delete(m.dirty, u.assignment.flow)
	}
	delete(m.pending, id)
	_ = m.cleanStale()
}
func flowRates(members map[uint32]rules.Policy, capacity uint64) (rate, ceil uint64) {
	for _, p := range members {
		if p.GBR() > rate {
			rate = p.GBR()
		}
		if cap := p.MBR(); cap != 0 && (ceil == 0 || cap < ceil) {
			ceil = cap
		}
	}
	if ceil == 0 || ceil > capacity {
		ceil = capacity
	}
	if rate == 0 {
		rate = 1000
		if rate > ceil {
			rate = ceil
		}
	}
	return
}
func (m *classManager) release(id uint32, a classAssignment) {
	if m.cfg.Mode != qosconfig.PerFlowHTB {
		return
	}
	f := m.flows[a.flow]
	if f == nil {
		return
	}
	delete(f.members, id)
	if len(f.members) == 0 {
		delete(m.flows, a.flow)
		m.totals[a.iface][f.parent] -= f.rate
		delete(m.dirty, a.flow)
		m.stale = append(m.stale, a)
		return
	}
	// A deleted stricter member may leave a conservative cap. Recalculate before
	// returning success so a remaining flow does not retain that stale cap.
	rate, ceil := flowRates(f.members, m.cfg.CapacityBps)
	if err := m.htb("change", a.iface, a.minor, f.parent, rate, ceil, 0); err == nil {
		m.totals[a.iface][f.parent] -= f.rate
		f.rate, f.ceil = rate, ceil
		m.totals[a.iface][f.parent] += f.rate
		delete(m.dirty, a.flow)
	} else {
		m.dirty[a.flow] = true
	}
}
func (m *classManager) Delete(id uint32) error {
	if _, ok := m.pending[id]; ok {
		if err := m.Rollback(id, false); err != nil {
			return err
		}
	}
	if a, ok := m.active[id]; ok {
		m.release(id, a)
		delete(m.active, id)
	}
	return m.cleanStale()
}
func (m *classManager) cleanStale() error {
	var kept []classAssignment
	var errs []error
	for _, a := range m.stale {
		if err := m.deleteClass(a); err != nil {
			kept = append(kept, a)
			errs = append(errs, err)
		}
	}
	m.stale = kept
	for key := range m.dirty {
		f := m.flows[key]
		rate, ceil := flowRates(f.members, m.cfg.CapacityBps)
		if err := m.htb("change", key.iface, f.assignment.minor, f.parent, rate, ceil, 0); err != nil {
			errs = append(errs, err)
			continue
		}
		m.totals[key.iface][f.parent] -= f.rate
		f.rate, f.ceil = rate, ceil
		m.totals[key.iface][f.parent] += f.rate
		delete(m.dirty, key)
	}
	return errors.Join(errs...)
}
func (m *classManager) deleteClass(a classAssignment) error {
	if err := m.run("class", "del", "dev", a.iface, "classid", fmt.Sprintf("e001:%x", a.minor)); err != nil {
		return err
	}
	delete(m.used[a.iface], a.minor)
	return nil
}
