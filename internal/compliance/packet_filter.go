package compliance

import (
	"fmt"
	"slices"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// PacketFilterComponent is the Component of a finding a plugin raises because
// packet filtering is disabled. It differs from the shared engine's finding for
// the same setting, so the de-duplication of engine findings against plugin
// findings keeps both.
const PacketFilterComponent = "packet-filter"

// PacketFilterFindingTitle is the Title of every finding FailWhenPacketFilterDisabled adds.
const PacketFilterFindingTitle = "Packet Filtering Disabled"

// PacketFilterRecommendation is the Recommendation of every finding
// FailWhenPacketFilterDisabled adds.
const PacketFilterRecommendation = "Re-enable packet filtering by clearing \"Disable all packet filtering\" " +
	"(OPNsense: Firewall > Settings > Advanced; pfSense: System > Advanced > Firewall & NAT)"

// PacketFilterDescription returns the Description of a finding for a control
// that packet filtering being disabled leaves unmet.
func PacketFilterDescription(controlTitle string) string {
	return fmt.Sprintf(
		"%s is not met: all packet filtering is disabled, so the firewall loads no rule, applies no "+
			"block option and performs no NAT, whatever the configuration lists",
		controlTitle,
	)
}

// FailWhenPacketFilterDisabled marks each control in controlIDs as evaluated
// and non-compliant when the device has packet filtering disabled. Both vendors
// run pfctl -d and return before any ruleset loads, so a control whose pass
// verdict means the firewall restricts, inspects, logs or translates traffic
// cannot pass, and its own check, which reads the configured rules, would
// otherwise report the box as protected. A control that already has a finding
// keeps it and gets no second one. newFinding builds the plugin's finding for a
// control ID.
//
//nolint:gocritic // nonamedreturns enforced project-wide; the doc comment states the return shape.
func FailWhenPacketFilterDisabled(
	device *common.CommonDevice,
	findings []Finding,
	evaluated []string,
	controlIDs []string,
	newFinding func(controlID string) Finding,
) ([]Finding, []string) {
	if device == nil || !device.System.PacketFilterDisabled {
		return findings, evaluated
	}

	for _, id := range controlIDs {
		if !slices.Contains(evaluated, id) {
			evaluated = append(evaluated, id)
		}

		if slices.ContainsFunc(findings, func(f Finding) bool { return referencesControl(f, id) }) {
			continue
		}

		findings = append(findings, newFinding(id))
	}

	return findings, evaluated
}

// referencesControl reports whether finding f was raised for control id.
func referencesControl(f Finding, id string) bool {
	return slices.Contains(f.References, id)
}
