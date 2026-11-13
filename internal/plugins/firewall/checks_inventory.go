// Package firewall provides a compliance plugin for firewall-specific security checks.
package firewall

import (
	"fmt"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// runInventoryChecks produces informational findings for configuration inventory.
// These use constants.FindingTypeInventory and are excluded from the compliance map — they
// are intentionally NOT appended to RunChecks' evaluated slice and therefore
// do not affect pass/fail status.
func (fp *Plugin) runInventoryChecks(device *common.CommonDevice) []compliance.Finding {
	var findings []compliance.Finding

	// FIREWALL-062: DHCP Scope Inventory
	if cr := fp.checkDHCPInventory(device); cr.Known && cr.Result {
		findings = append(findings, compliance.Finding{
			Type:        constants.FindingTypeInventory,
			Severity:    fp.controlSeverity("FIREWALL-062"),
			Title:       "DHCP Scopes Configured",
			Description: fp.dhcpInventoryDescription(device),
			Component:   "dhcp-config",
			Reference:   "FIREWALL-062",
			References:  []string{"FIREWALL-062"},
			Tags:        []string{"inventory", "dhcp", "firewall-controls"},
		})
	}

	// FIREWALL-063: Active Interface Summary
	if cr := fp.checkActiveInterfaces(device); cr.Known && cr.Result {
		findings = append(findings, compliance.Finding{
			Type:        constants.FindingTypeInventory,
			Severity:    fp.controlSeverity("FIREWALL-063"),
			Title:       "Active Interfaces",
			Description: fp.interfaceInventoryDescription(device),
			Component:   "interfaces",
			Reference:   "FIREWALL-063",
			References:  []string{"FIREWALL-063"},
			Tags:        []string{"inventory", "interfaces", "firewall-controls"},
		})
	}

	return findings
}

// checkDHCPInventory reports whether any DHCP scopes (ISC, Kea or dnsmasq) are configured.
func (fp *Plugin) checkDHCPInventory(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: device.HasDHCP(), Known: true}
}

// dhcpInventoryDescription builds a human-readable description of configured DHCP scopes,
// grouped by the DHCP server that serves them.
func (fp *Plugin) dhcpInventoryDescription(device *common.CommonDevice) string {
	if device == nil || len(device.DHCP) == 0 {
		return "No DHCP scopes configured"
	}

	var iscLabels, keaLabels, dnsmasqLabels []string
	for _, scope := range device.DHCP {
		label := scope.Interface
		if label == "" {
			label = scope.Description
		}
		if label == "" {
			label = "(unnamed)"
		}

		switch scope.Source {
		case common.DHCPSourceKea:
			keaLabels = append(keaLabels, label)
		case common.DHCPSourceDnsmasq:
			dnsmasqLabels = append(dnsmasqLabels, label)
		default:
			iscLabels = append(iscLabels, label)
		}
	}

	var parts []string
	if len(iscLabels) > 0 {
		parts = append(parts, fmt.Sprintf("%d ISC DHCP scope(s) on: %s",
			len(iscLabels), strings.Join(iscLabels, ", ")))
	}
	if len(keaLabels) > 0 {
		parts = append(parts, fmt.Sprintf("%d Kea subnet(s): %s",
			len(keaLabels), strings.Join(keaLabels, ", ")))
	}
	if len(dnsmasqLabels) > 0 {
		parts = append(parts, fmt.Sprintf("%d dnsmasq DHCP scope(s) on: %s",
			len(dnsmasqLabels), strings.Join(dnsmasqLabels, ", ")))
	}

	return strings.Join(parts, "; ")
}

// checkActiveInterfaces reports whether enabled interfaces exist.
func (fp *Plugin) checkActiveInterfaces(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	for _, iface := range device.Interfaces {
		if iface.Enabled {
			return checkResult{Result: true, Known: true}
		}
	}

	return checkResult{Result: false, Known: true}
}

// interfaceInventoryDescription builds a human-readable description of active interfaces.
func (fp *Plugin) interfaceInventoryDescription(device *common.CommonDevice) string {
	if device == nil {
		return "No interfaces configured"
	}

	var enabled int

	for _, iface := range device.Interfaces {
		if iface.Enabled {
			enabled++
		}
	}

	return fmt.Sprintf("%d enabled interface(s)", enabled)
}
