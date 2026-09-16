package pfcp

import (
	"github.com/free5gc/go-upf/internal/forwarder"
	qosmanager "github.com/free5gc/go-upf/internal/qos_manager"
	"github.com/free5gc/go-upf/internal/rules"
)

// updateQoSPolicies synchronizes successfully applied rules. Synchronization errors must not turn
// an already successful forwarding transaction into a PFCP failure response.
// Packet bindings are applied after policy updates; no TC/BPF operation occurs.
func (s *Session) updateQoSPolicies(changes *rules.RuleChangeSet, view qosmanager.RuleView) {
	if s.qos == nil {
		return
	}
	// Egress comes from deployment configuration; class selection remains
	// incomplete until the TC backend is connected.
	out, err := s.qos.Apply(changes, view, s.qosTarget)
	if err != nil {
		s.log.Errorf("QoS policy update failed; forwarding state remains applied: %v", err)
		return
	}
	if len(out.AddedPolicies)+len(out.UpdatedPolicies) == 0 {
		return
	}
	bindings, ok := s.datapath.(forwarder.FlowQoSDatapath)
	if !ok {
		s.log.Error("Datapath does not support FlowQoS binding")
		return
	}
	for _, keys := range [][]rules.PDRKey{out.AddedPolicies, out.UpdatedPolicies} {
		for _, key := range keys {
			p, ok := s.qos.Policy(key)
			if !ok {
				continue
			}
			// Identity marking does not require an egress class yet. Avoid
			// binding unsupported paths or unresolved QFI conflicts.
			valid := p.Direction == rules.Uplink || p.Direction == rules.Downlink
			for _, diagnostic := range p.Diagnostics {
				if diagnostic.Code == rules.AmbiguousQFI {
					valid = false
				}
			}
			if valid {
				err = bindings.SetFlowQoS(key.PDRID, p.ID)
			} else {
				err = bindings.ClearFlowQoS(key.PDRID)
			}
			if err != nil {
				s.log.Errorf("FlowQoS binding update failed for PDR %d: %v", key.PDRID, err)
			}
		}
	}
	// RemovedPolicies refer to already deleted PDRs. Kernel PDR destruction
	// owns binding cleanup; do not send an update to a nonexistent PDR.
}
