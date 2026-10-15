package forwarder

import (
	"fmt"

	"github.com/free5gc/go-gtp5gnl"
	"github.com/khirono/go-nl"
)

// FlowQoS updates PDR-local packet identity. Egress BPF selects the TC class.
type flowQoSBackend interface {
	updateFlowQoS(gtp5gnl.OID, nl.Attr) error
}

func (g *Gtp5g) updateFlowQoS(oid gtp5gnl.OID, attr nl.Attr) error {
	return gtp5gnl.UpdatePDROID(g.client, g.link.link, oid, []nl.Attr{attr})
}

func (s *sessionDatapath) SetFlowQoS(pdrID uint16, policyID uint32) error {
	if policyID == 0 {
		return fmt.Errorf("FlowQoS policy ID must be nonzero")
	}
	return s.updateFlowQoS(pdrID, gtp5gnl.FlowQoS{
		Version:  gtp5gnl.FLOW_QOS_BINDING_VERSION,
		PolicyID: policyID, Flags: gtp5gnl.FLOW_QOS_VALID,
	})
}

func (s *sessionDatapath) ClearFlowQoS(pdrID uint16) error {
	return s.updateFlowQoS(pdrID, gtp5gnl.FlowQoS{Version: gtp5gnl.FLOW_QOS_BINDING_VERSION})
}

func (s *sessionDatapath) updateFlowQoS(pdrID uint16, binding gtp5gnl.FlowQoS) error {
	current, ok := s.applied.pdrs[pdrID]
	if !ok {
		return fmt.Errorf("FlowQoS PDR %d is not applied in session %d", pdrID, s.localSEID)
	}
	attr, err := gtp5gnl.NewFlowQoSAttr(binding)
	if err != nil {
		return err
	}
	backend, ok := s.backend.(flowQoSBackend)
	if !ok {
		return fmt.Errorf("datapath does not support FlowQoS binding")
	}
	oid := gtp5gnl.OID{s.localSEID, uint64(pdrID)}
	if err := backend.updateFlowQoS(oid, attr); err != nil {
		return fmt.Errorf("FlowQoS PDR %d: %w", pdrID, err)
	}
	// Reuse the existing applied-attribute store so ordinary updates and
	// existing datapath restoration also preserve the confirmed binding.
	current.Attrs = mergeRuleAttrs(current.Attrs, []nl.Attr{attr})
	s.applied.pdrs[pdrID] = current
	return nil
}
