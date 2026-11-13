package audit

import (
	"regexp"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// Interface keys the anti-lockout rule is placed by. The vendor code matches
// the keys themselves, not the role an interface plays. Only the wan key is
// read as the WAN here, so a rule placed on an optN that is an uplink is not
// reported.
const (
	ifaceKeyWAN  = "wan"
	ifaceKeyLAN  = "lan"
	ifaceKeyOpt1 = "opt1"
)

// primaryInterfaceKey matches the keys OPNsense ranks for the anti-lockout rule
// ahead of wan (util.inc get_primary_interface_from_list).
var primaryInterfaceKey = regexp.MustCompile(`^(lan|opt\d+)$`)

// markImplicitWANExposure marks as WAN-reachable each management service that
// the firewall exposes without a rule in device.FirewallRules, which is all
// that wanRulePermitsPort reads. With packet filtering disabled pf is off and
// filters nothing, so every service is reachable from the WAN on its listening
// port. The web GUI and SSH listen on every address unless bound to chosen
// interfaces, which the model does not record, so this can over-report, the
// safe direction. The anti-lockout rule passes the web GUI and SSH ports
// (antiLockoutOnWAN).
func markImplicitWANExposure(device *common.CommonDevice, services []exposedService) {
	lockout := antiLockoutOnWAN(device)

	for i := range services {
		lockedOpen := lockout && (services[i].kind == exploitKindWebGUI || services[i].kind == exploitKindSSH)

		if device.System.PacketFilterDisabled || lockedOpen {
			services[i].reachability = analysis.WANReachable
		}
	}
}

// antiLockoutOnWAN reports whether the anti-lockout rule lands on the WAN. Both
// vendors add it unless <noantilockout> is set, as a quick pass rule ahead of
// every user rule, to the firewall's own web GUI port and, when SSH is enabled,
// its SSH port; the web GUI port 80 redirect it also passes is not a service
// here. Which interface gets it depends on the release, so the rule is read as
// landing on the WAN when any of them would put it there:
//
//   - OPNsense 23.1 and later take the first key of lan, optN and wan
//     (filter.lib.inc filter_core_get_antilockout), so the WAN gets it when no
//     lan or optN key exists, enabled or not. That is the shape the console's
//     WAN-only assignment writes.
//   - OPNsense up to 22.7 took lan, then opt1, when it had a device, and
//     otherwise wan when it was the only enabled interface.
//   - pfSense takes lan when there is more than one interface, and wan when it
//     is the only one, which the first case covers: pfSense keys are always
//     lan, wan or optN. The OPNsense 22.7 rule is not applied to pfSense, where
//     it would put the rule on a WAN that pfSense leaves without one.
func antiLockoutOnWAN(device *common.CommonDevice) bool {
	if device.System.WebGUI.NoAntiLockout {
		return false
	}

	var (
		wan, wanDevice, primary, legacyPrimary bool
		enabled                                int
	)

	for _, iface := range device.Interfaces {
		if iface.Enabled {
			enabled++
		}

		switch {
		case iface.Name == ifaceKeyWAN:
			wan = true
			wanDevice = iface.PhysicalIf != ""
		case primaryInterfaceKey.MatchString(iface.Name):
			primary = true
			legacyPrimary = legacyPrimary ||
				(iface.Name == ifaceKeyLAN || iface.Name == ifaceKeyOpt1) && iface.PhysicalIf != ""
		}
	}

	current := wan && !primary
	legacy := device.DeviceType != common.DeviceTypePfSense && wanDevice && !legacyPrimary && enabled == 1

	return current || legacy
}
