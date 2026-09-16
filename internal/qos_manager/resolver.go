package qosmanager

import "github.com/free5gc/go-upf/internal/rules"

// NewEgressResolver maps the supported Access/Core paths to deployment
// interfaces. Slice/class selection is supplied by the later TC backend.
// Arguments are captured by value; live remapping is not implemented.
func NewEgressResolver(n3, n6 string) TargetResolver {
	return func(_ rules.PDRKey, direction rules.Direction) (rules.Target, bool) {
		var egress string
		switch direction {
		case rules.Uplink:
			egress = n6
		case rules.Downlink:
			egress = n3
		}
		return rules.Target{Egress: egress}, egress != ""
	}
}

// Only PDR Source Interface determines direction in this backend. Other source
// interfaces stay unsupported; FAR and Linux interface names are not consulted.
func resolveDirection(p *rules.PDRConfig) rules.Direction {
	if p.PDI != nil {
		switch p.PDI.SourceInterface {
		case 0: // Access
			return rules.Uplink
		case 1: // Core
			return rules.Downlink
		}
	}
	return rules.Unknown
}
