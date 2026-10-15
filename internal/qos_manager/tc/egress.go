package tc

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/free5gc/go-upf/internal/rules"
)

type qosMapPolicy struct {
	Ifindex uint32
	ClassID uint32
}

// Bytes counts skb length at this egress, including any tunnel overhead.
// These are observation counters, not the future EDT accounting basis.
type qosCounters struct {
	Packets uint64
	Bytes   uint64
}
type TCEgress struct {
	objects    *ebpf.Collection
	links      []link.Link
	interfaces map[string]uint32
	classes    *classManager
}

func OpenTCEgress(names []string) (*TCEgress, error) {
	objects, err := ebpf.NewCollection(qosEgressSpec())
	if err != nil {
		return nil, fmt.Errorf("load BPF: %w", err)
	}
	e := &TCEgress{objects: objects, interfaces: make(map[string]uint32)}
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
	e.classes, err = openClasses(unique, runTC)
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
	// Detach only our links. Existing classifiers and qdiscs remain owned by
	// whoever installed them.
	var errs []error
	for _, attached := range e.links {
		errs = append(errs, attached.Close())
	}
	e.links = nil
	e.objects.Close()
	return errors.Join(append(errs, e.classes.Close())...)
}

func (e *TCEgress) PutQoSPolicy(p rules.Policy) (uint32, error) {
	if p.ID == 0 || p.ID > 0xffffff {
		return 0, fmt.Errorf("invalid QoS policy ID %d", p.ID)
	}
	if p.Target == nil || e.interfaces[p.Target.Egress] == 0 {
		return 0, fmt.Errorf("policy %d has no attached egress", p.ID)
	}
	classID, classCreated, err := e.classes.Prepare(p.ID, p.Target.Egress)
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
	value := qosMapPolicy{Ifindex: e.interfaces[p.Target.Egress], ClassID: classID}
	if err := e.objects.Maps["qos_policy"].Update(p.ID, value, ebpf.UpdateAny); err != nil {
		classErr := e.classes.Rollback(p.ID, classCreated)
		if statsCreated {
			cleanupErr := e.objects.Maps["qos_stats"].Delete(p.ID)
			if errors.Is(cleanupErr, ebpf.ErrKeyNotExist) {
				cleanupErr = nil
			}
			return 0, errors.Join(err, cleanupErr, classErr)
		}
		return 0, errors.Join(err, classErr)
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
	return e.classes.Delete(id)
}
