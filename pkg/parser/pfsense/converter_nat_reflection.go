package pfsense

import common "github.com/EvilBit-Labs/opnDossier/pkg/model"

// Port forward <natreflection> values (firewall_nat_edit.php). enable is
// NAT + proxy and purenat is pure NAT. The page offers default for the system
// setting but saves it by removing the element (firewall_nat.inc).
const (
	natReflectionEnable  = "enable"
	natReflectionPureNAT = "purenat"
	natReflectionDisable = "disable"
)

// natReflectionDisabled reports whether pfSense reflects none of the port
// forwards, the value NATConfig.ReflectionDisabled carries.
//
// filter_nat_rules_generate in filter.inc skips a disabled forward and picks
// a reflection type for each other one: none for disable, proxy for enable,
// pure NAT for purenat, and for any other value, default included, the
// system mode unless <system><disablenatreflection> is set. A no-RDR forward
// gets "no rdr" lines on the reflection interfaces, which reflect nothing.
// So a forward set to either Enable reflects on a firewall whose global mode
// is disabled, and one set to Disable is not reflected when it is on.
//
// With no forward that redirects, nothing is reflected yet and the global
// setting is what the next forward would inherit, so it decides.
//
// globalDisabled is read as the converter reads System.DisableNATReflection.
// filter.inc also skips reflection when a forward has no usable destination
// address or the firewall has no other interface to reflect on; that case is
// reported as reflected.
func natReflectionDisabled(forwards []common.InboundNATRule, globalDisabled bool) bool {
	redirects := false
	for _, r := range forwards {
		if r.Disabled || r.NoRDR {
			continue
		}
		redirects = true

		switch r.NATReflection {
		case natReflectionDisable:
		case natReflectionEnable, natReflectionPureNAT:
			return false
		default:
			if !globalDisabled {
				return false
			}
		}
	}

	if !redirects {
		return globalDisabled
	}

	return true
}
