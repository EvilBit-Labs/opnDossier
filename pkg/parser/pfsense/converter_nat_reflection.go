package pfsense

import common "github.com/EvilBit-Labs/opnDossier/pkg/model"

// Port forward <natreflection> values that reflect the forward
// (firewall_nat_edit.php): enable is NAT + proxy and purenat is pure NAT. The
// page offers default for the system setting but saves it by removing the
// element (firewall_nat.inc).
const (
	natReflectionEnable  = "enable"
	natReflectionPureNAT = "purenat"
)

// natReflectionDisabled reports whether NAT reflection is disabled: globally,
// and on every enabled port forward that redirects. This is the value
// NATConfig.ReflectionDisabled carries.
//
// filter_nat_rules_generate in filter.inc skips a disabled forward and picks
// a reflection type for each other one: none for disable, proxy for enable,
// pure NAT for purenat, and for any other value the system mode unless
// <system><disablenatreflection> is set. A no-RDR forward gets "no rdr" lines
// on the reflection interfaces, which reflect nothing. So a forward set to
// either Enable reflects on a firewall whose global mode is disabled.
//
// A global on makes the result false even when every forward opts out, since
// the next forward added would reflect. filter.inc also skips reflection when
// a forward has no usable destination address or the firewall has no other
// interface to reflect on; such a forward is still counted as reflected.
func natReflectionDisabled(forwards []common.InboundNATRule, globalDisabled bool) bool {
	if !globalDisabled {
		return false
	}

	for _, r := range forwards {
		if r.Disabled || r.NoRDR {
			continue
		}
		if r.NATReflection == natReflectionEnable || r.NATReflection == natReflectionPureNAT {
			return false
		}
	}

	return true
}
