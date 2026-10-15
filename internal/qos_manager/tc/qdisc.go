package tc

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// DRR selects a class from skb->priority. Its catch-all filter sends packets
// without a matching policy class to 1:1 instead of dropping them.
const qdiscMajor uint32 = 0xe0010000
const defaultMinor uint16 = 1

type tcRunner func(...string) error

func runTC(args ...string) error {
	out, err := exec.Command("tc", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

type classAssignment struct {
	iface string
	minor uint16
}

func (a classAssignment) id() uint32 { return qdiscMajor | uint32(a.minor) }

type classManager struct {
	run     tcRunner
	roots   []string
	active  map[uint32]classAssignment
	pending map[uint32]classAssignment
	stale   []classAssignment
	used    map[string]map[uint16]bool
}

func openClasses(names []string, run tcRunner) (*classManager, error) {
	m := &classManager{run: run, active: make(map[uint32]classAssignment),
		pending: make(map[uint32]classAssignment), used: make(map[string]map[uint16]bool)}
	for _, name := range names {
		if err := run("qdisc", "add", "dev", name, "root", "handle", "e001:", "drr"); err != nil {
			return nil, errors.Join(fmt.Errorf("create DRR root on %s: %w", name, err), m.Close())
		}
		m.roots = append(m.roots, name)
		m.used[name] = map[uint16]bool{defaultMinor: true}
		if err := run("class", "add", "dev", name, "parent", "e001:", "classid", "e001:1", "drr"); err != nil {
			return nil, errors.Join(fmt.Errorf("create default class on %s: %w", name, err), m.Close())
		}
		if err := run("filter", "add", "dev", name, "parent", "e001:", "protocol", "all", "matchall", "classid", "e001:1"); err != nil {
			return nil, errors.Join(fmt.Errorf("create default filter on %s: %w", name, err), m.Close())
		}
	}
	return m, nil
}

func (m *classManager) Close() error {
	var errs []error
	for i := len(m.roots) - 1; i >= 0; i-- {
		if err := m.run("qdisc", "del", "dev", m.roots[i], "root", "handle", "e001:"); err != nil {
			errs = append(errs, fmt.Errorf("remove DRR root on %s: %w", m.roots[i], err))
		}
	}
	m.roots = nil
	return errors.Join(errs...)
}

func (m *classManager) Prepare(policyID uint32, iface string) (uint32, bool, error) {
	if _, ok := m.pending[policyID]; ok {
		return 0, false, fmt.Errorf("policy %d has an unfinished TC class update", policyID)
	}
	if old, ok := m.active[policyID]; ok && old.iface == iface {
		return old.id(), false, nil
	}
	used, ok := m.used[iface]
	if !ok {
		return 0, false, fmt.Errorf("TC egress %s is not attached", iface)
	}
	for minor := uint32(defaultMinor) + 1; minor < 0xffff; minor++ {
		if used[uint16(minor)] {
			continue
		}
		a := classAssignment{iface: iface, minor: uint16(minor)}
		if err := m.run("class", "add", "dev", iface, "parent", "e001:", "classid", fmt.Sprintf("e001:%x", minor), "drr"); err != nil {
			return 0, false, fmt.Errorf("create class for policy %d: %w", policyID, err)
		}
		used[a.minor] = true
		m.pending[policyID] = a
		return a.id(), true, nil
	}
	return 0, false, fmt.Errorf("TC classes exhausted on %s", iface)
}

func (m *classManager) Rollback(policyID uint32, created bool) error {
	if !created {
		return nil
	}
	a, ok := m.pending[policyID]
	if !ok {
		return nil
	}
	if err := m.deleteClass(a); err != nil {
		return err
	}
	delete(m.pending, policyID)
	return nil
}

func (m *classManager) Commit(policyID uint32) {
	a, ok := m.pending[policyID]
	if !ok {
		return
	}
	old, hadOld := m.active[policyID]
	m.active[policyID] = a
	delete(m.pending, policyID)
	if hadOld {
		m.stale = append(m.stale, old)
	}
	// The new class and map are already live. Retain any old class that could
	// not be removed yet, and retry cleanup on deletion or the next update.
	_ = m.cleanStale()
}

func (m *classManager) Delete(policyID uint32) error {
	var errs []error
	if a, ok := m.active[policyID]; ok {
		if err := m.deleteClass(a); err != nil {
			errs = append(errs, err)
		} else {
			delete(m.active, policyID)
		}
	}
	if a, ok := m.pending[policyID]; ok {
		if err := m.deleteClass(a); err != nil {
			errs = append(errs, err)
		} else {
			delete(m.pending, policyID)
		}
	}
	err := m.cleanStale()
	return errors.Join(append(errs, err)...)
}

func (m *classManager) cleanStale() error {
	var kept []classAssignment
	var errs []error
	for _, a := range m.stale {
		if err := m.deleteClass(a); err != nil {
			errs = append(errs, err)
			kept = append(kept, a)
		}
	}
	m.stale = kept
	return errors.Join(errs...)
}

func (m *classManager) deleteClass(a classAssignment) error {
	if err := m.run("class", "del", "dev", a.iface, "classid", fmt.Sprintf("e001:%x", a.minor)); err != nil {
		return fmt.Errorf("delete class %x on %s: %w", a.minor, a.iface, err)
	}
	delete(m.used[a.iface], a.minor)
	return nil
}
