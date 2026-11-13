package opnsense

import common "github.com/EvilBit-Labs/opnDossier/pkg/model"

// Port forward <natreflection> values that reflect the forward
// (ForwardRule.php). The 26.1 model writes purenat for Enable; enable is what
// the firewall fills in for a forward that inherits the system default.
const (
	natReflectionPureNAT = "purenat"
	natReflectionEnable  = "enable"
)

// natReflectionDisabled reports whether the firewall reflects none of the
// port forwards, the value NATConfig.ReflectionDisabled carries.
//
// Reflection is decided per forward. The firewall plugin (Plugin.php,
// registerDestinationNatRule) gives a forward whose <natreflection> is
// empty the system default, enable unless <system><disablenatreflection> is
// set, and ForwardRule.php reflects a forward that is not disabled, is not a
// no-RDR rule, and ends up with purenat or enable. So one forward set to
// Enable is reflected on a firewall whose global setting is off, and a
// forward set to Disable is not reflected on one whose global setting is on.
// The logic is the same from 18.1 through 26.7.
//
// With no forward that redirects, nothing is reflected yet and the global
// setting is what the next forward would inherit, so it decides.
//
// globalDisabled is read as the converter reads System.DisableNATReflection.
// The firewall may still skip a reflected forward it cannot load, such as one
// with no valid target; that case is reported as reflected.
func natReflectionDisabled(forwards []common.InboundNATRule, globalDisabled bool) bool {
	redirects := false
	for _, r := range forwards {
		if r.Disabled || r.NoRDR {
			continue
		}
		redirects = true

		mode := r.NATReflection
		// PHP's empty() is true for "0" as well as "".
		if (mode == "" || mode == "0") && !globalDisabled {
			mode = natReflectionEnable
		}
		if mode == natReflectionPureNAT || mode == natReflectionEnable {
			return false
		}
	}

	if !redirects {
		return globalDisabled
	}

	return true
}
