package tc

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	qosconfig "github.com/free5gc/go-upf/internal/qos_manager/config"
	"github.com/free5gc/go-upf/internal/rules"
)

type qosMapPolicy struct {
	Ifindex uint32
	ClassID uint32
}

// Bytes counts skb length at this egress, including any tunnel overhead.
// These observation counters include packets later dropped by EDT. EDT also
// uses egress skb bytes; it does not yet parse the inner UE IP packet length.
type qosCounters struct {
	Packets uint64
	Bytes   uint64
}
type TCEgress struct {
	objects    *ebpf.Collection
	links      []link.Link
	interfaces map[string]uint32
	classes    *classManager
	rates      *rateManager
}

func OpenTCEgress(names []string, options ...qosconfig.Config) (*TCEgress, error) {
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
	spec := qosEgressSpec()
	if cfg.Mode == qosconfig.SharedHTBEDT {
		addEDT(spec, cfg.HorizonMS)
	}
	objects, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF: %w", err)
	}
	e := &TCEgress{objects: objects, interfaces: make(map[string]uint32)}
	if cfg.Mode == qosconfig.SharedHTBEDT {
		e.rates = newRateManager(objects)
	}
	var unique []string
	for _, name := range names {
		if _, ok := e.interfaces[name]; ok {
			continue
		}
		iface, err := net.InterfaceByName(name)
		if err != nil {
			objects.Close()
			return nil, err
		}
		e.interfaces[name] = uint32(iface.Index)
		unique = append(unique, name)
	}
	e.classes, err = openClasses(unique, runTC, cfg)
	if err != nil {
		objects.Close()
		return nil, err
	}
	for _, name := range unique {
		attached, err := link.AttachTCX(link.TCXOptions{Interface: int(e.interfaces[name]), Program: objects.Programs["qos_egress"], Attach: ebpf.AttachTCXEgress})
		if err != nil {
			return nil, errors.Join(fmt.Errorf("attach TCX egress %s: %w", name, err), e.Close())
		}
		e.links = append(e.links, attached)
	}
	return e, nil
}

func (e *TCEgress) Close() error {
	// Detach our links and remove only the roots created by openClasses.
	var errs []error
	for _, attached := range e.links {
		errs = append(errs, attached.Close())
	}
	e.links = nil
	e.objects.Close()
	return errors.Join(append(errs, e.classes.Close())...)
}

// ValidateQoSPolicies checks datapath bounds during PFCP validation, before
// forwarding or TC is changed. It visits derived rates, not PDR.QERIDs again.
func (e *TCEgress) ValidateQoSPolicies(policies []rules.Policy) error {
	added := make(map[rateKey]map[uint32]bool)
	for _, p := range policies {
		if p.Target == nil {
			continue
		}
		if p.Target.Slice != "" {
			return fmt.Errorf("TC modes currently support one local hierarchy, not slice %q", p.Target.Slice)
		}
		if p.GBR() > e.classes.cfg.BudgetFor(p.Target.Egress).GBRBps {
			return fmt.Errorf("PDR %d GBR exceeds the configured GBR service budget", p.Key.PDRID)
		}
		if e.rates == nil {
			continue
		}
		key := sessionRateKey(p)
		if added[key] == nil {
			added[key] = make(map[uint32]bool)
		}
		count := 0
		for _, rate := range p.Rates {
			if rate.MBRBps == 0 {
				continue
			}
			count++
			if session := e.rates.sessions[key]; session != nil {
				if _, exists := session.slots[rate.QERID]; exists {
					continue
				}
			}
			added[key][rate.QERID] = true
		}
		if count > MaxPolicyRates {
			return fmt.Errorf("PDR %d exceeds %d MBR constraints", p.Key.PDRID, MaxPolicyRates)
		}
		used := 0
		if session := e.rates.sessions[key]; session != nil {
			used = len(session.slots)
		}
		if used+len(added[key]) > maxSessionRates {
			return fmt.Errorf("session %d direction %d exceeds %d QER rate slots", key.SEID, key.Direction, maxSessionRates)
		}
	}
	return nil
}

func (e *TCEgress) PutQoSPolicy(p rules.Policy) (uint32, error) {
	if p.ID == 0 || p.ID > 0xffffff {
		return 0, fmt.Errorf("invalid QoS policy ID %d", p.ID)
	}
	if p.Target == nil || e.interfaces[p.Target.Egress] == 0 {
		return 0, fmt.Errorf("policy %d has no attached egress", p.ID)
	}
	classID, classCreated, err := e.classes.Prepare(p)
	if err != nil {
		return 0, err
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return 0, errors.Join(err, e.classes.Rollback(p.ID, classCreated))
	}
	// Initialize once; updates retain counters.
	err = e.objects.Maps["qos_stats"].Update(p.ID, make([]qosCounters, cpus), ebpf.UpdateNoExist)
	if err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
		return 0, errors.Join(err, e.classes.Rollback(p.ID, classCreated))
	}
	statsCreated := err == nil
	var rollbackRates func() error
	var commitRates func()
	if e.rates != nil {
		if err := e.objects.Maps["qos_drops"].Update(p.ID, make([][3]uint64, cpus), ebpf.UpdateNoExist); err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
			return 0, errors.Join(err, e.classes.Rollback(p.ID, classCreated))
		}
		rollbackRates, commitRates, err = e.rates.Prepare(p)
		if err != nil {
			return 0, errors.Join(err, e.classes.Rollback(p.ID, classCreated))
		}
	}
	value := qosMapPolicy{Ifindex: e.interfaces[p.Target.Egress], ClassID: classID}
	if err := e.objects.Maps["qos_policy"].Update(p.ID, value, ebpf.UpdateAny); err != nil {
		classErr := e.classes.Rollback(p.ID, classCreated)
		if rollbackRates != nil {
			classErr = errors.Join(classErr, rollbackRates())
		}
		if statsCreated {
			cleanupErr := e.objects.Maps["qos_stats"].Delete(p.ID)
			if errors.Is(cleanupErr, ebpf.ErrKeyNotExist) {
				cleanupErr = nil
			}
			return 0, errors.Join(err, cleanupErr, classErr)
		}
		return 0, errors.Join(err, classErr)
	}
	if commitRates != nil {
		commitRates()
	}
	e.classes.Commit(p.ID)
	return classID, nil
}
func (e *TCEgress) DeleteQoSPolicy(id uint32) error {
	for _, name := range []string{"qos_policy", "qos_stats"} {
		if err := e.objects.Maps[name].Delete(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	if e.rates != nil {
		if err := e.rates.Delete(id); err != nil {
			return err
		}
		if err := e.objects.Maps["qos_drops"].Delete(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return e.classes.Delete(id)
}
