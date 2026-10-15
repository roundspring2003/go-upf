package qosmanager

import "github.com/free5gc/go-upf/internal/rules"

// NewEgressResolver maps the supported Access/Core paths to deployment
// interfaces. TC class IDs are assigned when policies are published.
// Arguments are captured by value; live remapping is not implemented.
func NewEgressResolver(n3, n6 rules.Target) TargetResolver {
	return func(_ rules.PDRKey, direction rules.Direction) (rules.Target, bool) {
		var target rules.Target
		switch direction {
		case rules.Uplink:
			target = n6
		case rules.Downlink:
			target = n3
		}
		return target, target.Egress != ""
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
