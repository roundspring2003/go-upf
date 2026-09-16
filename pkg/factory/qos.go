package factory

import (
	"fmt"
	"net"
)

// ValidateQoSEgress checks the UPF's current network namespace before any
// driver resources are created. It does not change routes or install TC.
func (c *Config) ValidateQoSEgress() error {
	return validateQoSEgress(c.QoS, net.InterfaceByName)
}

func validateQoSEgress(q *QoS, lookup func(string) (*net.Interface, error)) error {
	if q == nil {
		return nil
	}
	for _, name := range []string{q.N3Egress, q.N6Egress} {
		if name == "" {
			return fmt.Errorf("qos.n3Egress and qos.n6Egress must both be configured")
		}
		iface, err := lookup(name)
		if err != nil {
			return fmt.Errorf("QoS egress %q is unavailable in this network namespace: %w", name, err)
		}
		if iface.Flags&net.FlagLoopback != 0 || name == "upfgtp" {
			return fmt.Errorf("QoS egress %q must be an external interface, not loopback or upfgtp", name)
		}
	}
	return nil
}
