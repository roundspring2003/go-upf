package tc

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/free5gc/go-upf/internal/rules"
)

// Bounds keep the datapath verifier-friendly. They count rate-bearing QERs,
// not all QER references. Slots are not reused while a session direction is live.
const MaxPolicyRates = 8
const maxSessionRates = 64

type rateKey struct {
	SEID      uint64
	Direction uint32
	Pad       uint32
}
type rateSlot struct {
	Bps  uint64
	Slot uint32
	Pad  uint32
}
type ratePolicy struct {
	Key   rateKey
	Rates [MaxPolicyRates]rateSlot
}
type rateRuntime struct {
	Lock uint32
	Pad  uint32
	Next [maxSessionRates]uint64
}
type rateSession struct {
	slots    map[uint32]uint32
	policies map[uint32]bool
}
type rateManager struct {
	configs, runtime *ebpf.Map
	sessions         map[rateKey]*rateSession
	policies         map[uint32]ratePolicy
}

func newRateManager(objects *ebpf.Collection) *rateManager {
	return &rateManager{configs: objects.Maps["qos_rate_policy"], runtime: objects.Maps["qos_runtime"], sessions: make(map[rateKey]*rateSession), policies: make(map[uint32]ratePolicy)}
}
func sessionRateKey(p rules.Policy) rateKey {
	k := rateKey{SEID: p.Key.SEID}
	if p.Direction == rules.Downlink {
		k.Direction = 1
	}
	return k
}

// Prepare preserves virtual time on rate updates. In particular, replacing a
// policy never resets a shared QER clock and never grants a fresh burst budget.
func (m *rateManager) Prepare(p rules.Policy) (func() error, func(), error) {
	key := sessionRateKey(p)
	session := m.sessions[key]
	if session == nil {
		if err := m.runtime.Update(key, rateRuntime{}, ebpf.UpdateNoExist); err != nil {
			return nil, nil, err
		}
		session = &rateSession{slots: make(map[uint32]uint32), policies: make(map[uint32]bool)}
		m.sessions[key] = session
	}
	value := ratePolicy{Key: key}
	n := 0
	for _, r := range p.Rates {
		if r.MBRBps == 0 {
			continue
		}
		if n == MaxPolicyRates {
			return nil, nil, errors.Join(fmt.Errorf("too many MBR constraints"), m.discardUnused(key))
		}
		slot, ok := session.slots[r.QERID]
		if !ok {
			if len(session.slots) == maxSessionRates {
				return nil, nil, fmt.Errorf("session %d direction %d exhausted %d QER rate slots", key.SEID, key.Direction, maxSessionRates)
			}
			slot = uint32(len(session.slots))
			session.slots[r.QERID] = slot
		}
		value.Rates[n] = rateSlot{Bps: r.MBRBps, Slot: slot}
		n++
	}
	old, hadOld := m.policies[p.ID]
	if err := m.configs.Update(p.ID, value, ebpf.UpdateAny); err != nil {
		return nil, nil, errors.Join(err, m.discardUnused(key))
	}
	rollback := func() error {
		var err error
		if hadOld {
			err = m.configs.Update(p.ID, old, ebpf.UpdateAny)
		} else {
			err = m.configs.Delete(p.ID)
		}
		return errors.Join(err, m.discardUnused(key))
	}
	commit := func() {
		if hadOld && old.Key != key {
			delete(m.sessions[old.Key].policies, p.ID)
			_ = m.discardUnused(old.Key)
		}
		session.policies[p.ID] = true
		m.policies[p.ID] = value
	}
	return rollback, commit, nil
}
func (m *rateManager) discardUnused(key rateKey) error {
	session := m.sessions[key]
	if session == nil || len(session.policies) != 0 {
		return nil
	}
	if err := m.runtime.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	delete(m.sessions, key)
	return nil
}
func (m *rateManager) Delete(id uint32) error {
	if err := m.configs.Delete(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	old, ok := m.policies[id]
	if !ok {
		return nil
	}
	delete(m.policies, id)
	delete(m.sessions[old.Key].policies, id)
	return m.discardUnused(old.Key)
}
