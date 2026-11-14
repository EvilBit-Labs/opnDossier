package firewall

import (
	"slices"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// packetFilterControls are the controls whose pass verdict means pf restricts
// or logs traffic: no rule passes everything, WAN sources are narrowed, ports
// and protocols are pinned, pass and filter events are logged, private and
// bogon networks are blocked on the WAN, and VLANs are kept apart. With packet filtering disabled none of
// that happens, whatever the rules say. Controls about the configuration
// itself, such as rule descriptions or the NAT reflection setting, are left to
// their own checks.
var packetFilterControls = []string{
	"FIREWALL-022",
	"FIREWALL-023",
	"FIREWALL-024",
	"FIREWALL-027",
	"FIREWALL-028",
	"FIREWALL-029",
	"FIREWALL-030",
	"FIREWALL-032",
	"FIREWALL-041",
}

// failPacketFilterControls fails packetFilterControls when packet filtering is
// disabled (compliance.FailWhenPacketFilterDisabled) and returns RunChecks'
// results, so that RunChecks can end with it.
//
//nolint:gocritic // nonamedreturns enforced project-wide; mirrors RunChecks' return shape.
func (fp *Plugin) failPacketFilterControls(
	device *common.CommonDevice,
	findings []compliance.Finding,
	evaluated []string,
) ([]compliance.Finding, []string, error) {
	findings, evaluated = compliance.FailWhenPacketFilterDisabled(device, findings, evaluated, packetFilterControls,
		func(id string) compliance.Finding {
			var title string
			var tags []string

			if ctrl, err := fp.GetControlByID(id); err == nil {
				title = ctrl.Title
				tags = slices.Clone(ctrl.Tags)
			}

			return compliance.Finding{
				Type:           constants.FindingTypeCompliance,
				Severity:       fp.controlSeverity(id),
				Title:          compliance.PacketFilterFindingTitle,
				Description:    compliance.PacketFilterDescription(title),
				Recommendation: compliance.PacketFilterRecommendation,
				Component:      compliance.PacketFilterComponent,
				Reference:      id,
				References:     []string{id},
				Tags:           tags,
			}
		})

	return findings, evaluated, nil
}
