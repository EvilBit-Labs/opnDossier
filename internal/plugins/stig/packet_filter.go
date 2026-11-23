package stig

import (
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// packetFilterControls are the controls whose pass verdict means pf filters or
// logs traffic: default deny, filtering on packet attributes, rate limits on
// pass rules and traffic logging. With packet filtering disabled none of that
// happens, whatever the rules say.
var packetFilterControls = []string{
	"V-206694",
	"V-206674",
	"V-206701",
	"V-206682",
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
			var tags []string

			if ctrl, err := sp.GetControlByID(id); err == nil {
				title = ctrl.Title
				tags = append(tags, ctrl.Tags...)
			}

			return compliance.Finding{
				Type:           constants.FindingTypeCompliance,
				Severity:       sp.controlSeverity(id),
				Title:          compliance.PacketFilterFindingTitle,
				Description:    compliance.PacketFilterDescription(title),
				Recommendation: compliance.PacketFilterRecommendation,
				Component:      compliance.PacketFilterComponent,
				Reference:      "STIG " + id,
				References:     []string{id},
				Tags:           append(tags, "stig"),
			}
		})

	return findings, evaluated, nil
}
