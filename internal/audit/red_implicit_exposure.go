package audit

import (
	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// markImplicitWANExposure marks as WAN-reachable each management service that
// the firewall exposes without a rule in device.FirewallRules, which is all
// that wanRulePermitsPort reads. With packet filtering disabled pf is off and
// filters nothing, so every service is reachable from the WAN on its listening
// port. The web GUI and SSH listen on every address unless bound to chosen
// interfaces, which the model does not record, so this can over-report, the
// safe direction.
func markImplicitWANExposure(device *common.CommonDevice, services []exposedService) {
	if !device.System.PacketFilterDisabled {
		return
	}

	for i := range services {
		services[i].reachability = analysis.WANReachable
	}
}
