package pfcp

import qosmanager "github.com/free5gc/go-upf/internal/qos_manager"

// updateQoSPolicies publishes the prepared TC policies after forwarding and
// session rules succeed, then binds PDRs. TC I/O errors do not undo forwarding.
func (s *Session) updateQoSPolicies(plan *qosmanager.Prepared) {
	if s.qos == nil {
		return
	}
	out, err := s.qos.ApplyPrepared(plan)
	if err != nil {
		s.log.Errorf("QoS policy update failed; forwarding state remains applied: %v", err)
	}
	if len(out.SetBindings)+len(out.ClearBindings) == 0 {
		return
	}
	for _, key := range out.SetBindings {
		p, ok := s.qos.Policy(key)
		if !ok {
			continue
		}
		if err := s.datapath.SetFlowQoS(key.PDRID, p.ID); err != nil {
			s.log.Errorf("FlowQoS binding update failed for PDR %d: %v", key.PDRID, err)
		}
	}
	for _, key := range out.ClearBindings {
		if err := s.datapath.ClearFlowQoS(key.PDRID); err != nil {
			s.log.Errorf("FlowQoS binding update failed for PDR %d: %v", key.PDRID, err)
		}
	}
	// Removed PDRs are already deleted; kernel PDR destruction clears their binding.
}
