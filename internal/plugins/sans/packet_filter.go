package sans

import (
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// packetFilterControls are the controls whose pass verdict means pf filters,
// inspects or translates traffic: default deny, explicit rules, separation
// between zones, stateful inspection, anti-spoofing, the per-service port
// restrictions, ICMP and egress filtering, masquerading and TCP state checks.
// With packet filtering disabled none of that happens, whatever the rules say.
// Controls about the configuration itself, such as rule order or firmware, are
// left to their own checks.
var packetFilterControls = []string{
	"SANS-FW-001",
	"SANS-FW-002",
	"SANS-FW-003",
	"SANS-FW-007",
	"SANS-FW-012",
	"SANS-FW-014",
	"SANS-FW-016",
	"SANS-FW-017",
	"SANS-FW-018",
	"SANS-FW-019",
	"SANS-FW-020",
	"SANS-FW-021",
	"SANS-FW-022",
	"SANS-FW-024",
}

// failPacketFilterControls fails packetFilterControls when packet filtering is
// disabled (compliance.FailWhenPacketFilterDisabled) and returns RunChecks'
// results, so that RunChecks can end with it.
//
//nolint:gocritic // nonamedreturns enforced project-wide; mirrors RunChecks' return shape.
func (sp *Plugin) failPacketFilterControls(
	device *common.CommonDevice,
	findings []compliance.Finding,
	evaluated []string,
) ([]compliance.Finding, []string, error) {
	findings, evaluated = compliance.FailWhenPacketFilterDisabled(device, findings, evaluated, packetFilterControls,
		func(id string) compliance.Finding {
			var title string
			if ctrl, err := sp.GetControlByID(id); err == nil {
				title = ctrl.Title
			}

			return sp.finding(
				id,
				compliance.PacketFilterFindingTitle,
				compliance.PacketFilterDescription(title),
				compliance.PacketFilterRecommendation,
				compliance.PacketFilterComponent,
			)
		})

	return findings, evaluated, nil
}
