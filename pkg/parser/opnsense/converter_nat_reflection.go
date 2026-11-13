package opnsense

import common "github.com/EvilBit-Labs/opnDossier/pkg/model"

// Port forward <natreflection> values that reflect the forward
// (ForwardRule.php). The 26.1 model writes purenat for Enable; enable is what
// the firewall fills in for a forward that inherits a global enable.
const (
	natReflectionPureNAT = "purenat"
	natReflectionEnable  = "enable"
)

// natReflectionDisabled reports whether NAT reflection is disabled: globally,
// and on every enabled port forward that redirects. This is the value
// NATConfig.ReflectionDisabled carries.
//
// The firewall plugin (Plugin.php) makes enable the forward default only when
// <system><disablenatreflection> is empty, and ForwardRule.php reflects a
// forward that is not disabled, is not a no-RDR rule, and ends up with
// purenat or enable. So a forward set to Enable is reflected on a firewall
// whose global setting is off. How the default is filled in changed at 26.1:
// up to 25.7 registerForwardRule used array_merge, which fills only an absent
// <natreflection>, and from 26.1 it fills any value empty() accepts, "" and
// "0" included. Under a global off the default is off either way, so only an
// explicit purenat or enable decides here.
//
// A global on makes the result false even when every forward opts out, since
// the next forward added would reflect. Forwards the firewall drops at load
// time, such as one with no valid target, are still counted as reflected.
func natReflectionDisabled(forwards []common.InboundNATRule, globalDisabled bool) bool {
	if !globalDisabled {
		return false
	}

	for _, r := range forwards {
		if r.Disabled || r.NoRDR {
			continue
		}
		if r.NATReflection == natReflectionPureNAT || r.NATReflection == natReflectionEnable {
			return false
		}
	}

	return true
}
