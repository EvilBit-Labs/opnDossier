package sans

import (
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// dangerousPorts lists service ports that should never be exposed on WAN.
var dangerousPorts = []string{
	"23",   // Telnet
	"135",  // MS RPC
	"136",  // Profile Naming System
	"137",  // NetBIOS Name Service
	"138",  // NetBIOS Datagram Service
	"139",  // NetBIOS Session Service
	"161",  // SNMP
	"162",  // SNMP Trap
	"445",  // SMB/CIFS
	"2049", // NFS
}

// defaultUsernames contains factory-default account names that indicate
// credentials have not been customized. Comparisons are case-insensitive.
var defaultUsernames = []string{"admin", "root"}

// appLayerProxyPackages lists package names that provide application-layer filtering.
var appLayerProxyPackages = []string{
	"os-haproxy",
	"os-squid",
	"os-nginx",
	"os-postfix",
	"os-ftp-proxy",
	"haproxy",
	"squid",
}

// isWANInterface reports whether the interface name represents a WAN interface.
func isWANInterface(name string) bool {
	lower := strings.ToLower(name)
	return lower == "wan" || strings.HasPrefix(lower, "wan")
}

// isDMZOrOPTInterface reports whether the interface name represents a DMZ or OPT interface.
func isDMZOrOPTInterface(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "dmz") ||
		strings.HasPrefix(lower, "opt")
}

// enabledPassRules returns all enabled pass rules from the device.
func enabledPassRules(device *common.CommonDevice) []common.FirewallRule {
	var rules []common.FirewallRule
	for _, r := range device.FirewallRules {
		if !r.Disabled && r.Type == common.RuleTypePass {
			rules = append(rules, r)
		}
	}
	return rules
}

// ruleAppliesToWAN reports whether a firewall rule applies to any WAN interface.
func ruleAppliesToWAN(rule common.FirewallRule) bool {
	return slices.ContainsFunc(rule.Interfaces, isWANInterface)
}

// portMatchesDangerous checks whether a port specification matches any dangerous port.
// Handles exact matches and simple ranges (e.g., "135-139").
func portMatchesDangerous(port string) bool {
	if port == "" {
		return false
	}
	for _, dp := range dangerousPorts {
		if port == dp {
			return true
		}
		// Check if the dangerous port falls within a range like "135-139".
		//nolint:mnd // 2 is the expected number of parts in a port range "start-end"
		if parts := strings.SplitN(port, "-", 2); len(parts) == 2 {
			if dp >= parts[0] && dp <= parts[1] {
				return true
			}
		}
	}
	return false
}

// checkDefaultDeny verifies the firewall has a default deny policy.
// If no rules exist, OPNsense/pfSense default deny is assumed compliant.
// If pass rules exist without any block/reject rules, it fails.
func (sp *Plugin) checkDefaultDeny(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	rules := device.FirewallRules
	if len(rules) == 0 {
		// No rules — default deny is implicit on OPNsense/pfSense.
		return checkResult{Result: true, Known: true}
	}

	hasBlock := false
	hasAnyAnyPass := false

	for _, r := range rules {
		if r.Disabled {
			continue
		}
		if r.Type == common.RuleTypeBlock || r.Type == common.RuleTypeReject {
			hasBlock = true
		}
		if r.Type == common.RuleTypePass &&
			r.Source.Address == constants.NetworkAny &&
			r.Destination.Address == constants.NetworkAny {
			hasAnyAnyPass = true
		}
	}

	// Fail if there is an any-any pass without any block rules.
	if hasAnyAnyPass && !hasBlock {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: true, Known: true}
}

// checkExplicitRules verifies all enabled pass rules have non-empty descriptions.
func (sp *Plugin) checkExplicitRules(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	passRules := enabledPassRules(device)
	if len(passRules) == 0 {
		return checkResult{Result: true, Known: true}
	}

	for _, r := range passRules {
		if strings.TrimSpace(r.Description) == "" {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkZoneSeparation verifies the device has at least 2 enabled interfaces
// for network zone separation.
func (sp *Plugin) checkZoneSeparation(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	enabledCount := 0
	for _, iface := range device.Interfaces {
		if iface.Enabled {
			enabledCount++
		}
	}

	//nolint:mnd // Zone separation requires at minimum 2 interfaces (e.g., WAN + LAN)
	return checkResult{Result: enabledCount >= 2, Known: true}
}

// checkComprehensiveLogging verifies syslog is enabled with at least
// filter or auth logging active.
func (sp *Plugin) checkComprehensiveLogging(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	if !device.Syslog.Enabled {
		return checkResult{Result: false, Known: true}
	}

	hasSubLogging := device.Syslog.FilterLogging || device.Syslog.AuthLogging
	return checkResult{Result: hasSubLogging, Known: true}
}

// checkRulesetOrdering verifies that block/reject rules appear before pass rules.
// This ensures anti-spoofing protections are evaluated first.
func (sp *Plugin) checkRulesetOrdering(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	rules := device.FirewallRules
	if len(rules) == 0 {
		return checkResult{Result: true, Known: true}
	}

	seenPass := false
	seenBlockAfterPass := false

	for _, r := range rules {
		if r.Disabled {
			continue
		}
		if r.Type == common.RuleTypePass {
			seenPass = true
		}
		if seenPass && (r.Type == common.RuleTypeBlock || r.Type == common.RuleTypeReject) {
			seenBlockAfterPass = true
		}
	}

	// If there are block rules after pass rules, ordering is suboptimal but
	// still valid. We specifically check whether ALL block rules come before
	// the first pass rule.
	firstPassIdx := -1
	lastBlockIdx := -1

	for i, r := range rules {
		if r.Disabled {
			continue
		}
		if r.Type == common.RuleTypePass && firstPassIdx == -1 {
			firstPassIdx = i
		}
		if r.Type == common.RuleTypeBlock || r.Type == common.RuleTypeReject {
			lastBlockIdx = i
		}
	}

	// No block rules at all — can't verify ordering, but no anti-spoofing present.
	if lastBlockIdx == -1 {
		// If there are pass rules but no blocks, we cannot confirm ordering.
		if seenPass {
			return checkResult{Result: false, Known: true}
		}
		return checkResult{Result: true, Known: true}
	}

	// No pass rules — ordering is trivially correct.
	if firstPassIdx == -1 {
		return checkResult{Result: true, Known: true}
	}

	// If all block rules appear before the first pass rule.
	_ = seenBlockAfterPass
	return checkResult{Result: lastBlockIdx < firstPassIdx, Known: true}
}

// checkAppLayerFiltering checks for installed proxy packages that provide
// application-layer filtering. This is a PARTIAL check.
func (sp *Plugin) checkAppLayerFiltering(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	for _, pkg := range device.Packages {
		if !pkg.Installed {
			continue
		}
		pkgLower := strings.ToLower(pkg.Name)
		if slices.Contains(appLayerProxyPackages, pkgLower) {
			return checkResult{Result: true, Known: true}
		}
	}

	// Also check firmware plugins string.
	for plugin := range strings.SplitSeq(device.System.Firmware.Plugins, ",") {
		pluginLower := strings.ToLower(strings.TrimSpace(plugin))
		if slices.Contains(appLayerProxyPackages, pluginLower) {
			return checkResult{Result: true, Known: true}
		}
	}

	return checkResult{Result: false, Known: true}
}

// checkStatefulInspection verifies all TCP pass rules have a StateType
// containing "state" (e.g., "keep state", "sloppy state").
func (sp *Plugin) checkStatefulInspection(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	hasTCPPass := false
	for _, r := range enabledPassRules(device) {
		if !strings.EqualFold(r.Protocol, "tcp") {
			continue
		}
		hasTCPPass = true
		if !strings.Contains(strings.ToLower(r.StateType), "state") {
			return checkResult{Result: false, Known: true}
		}
	}

	if !hasTCPPass {
		// No TCP pass rules — cannot evaluate.
		return unknown
	}

	return checkResult{Result: true, Known: true}
}

// checkFirmwareCurrency verifies the firmware version string is present.
// This is a PARTIAL check — it confirms version exists but cannot verify currency.
func (sp *Plugin) checkFirmwareCurrency(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{
		Result: strings.TrimSpace(device.System.Firmware.Version) != "",
		Known:  true,
	}
}

// checkDMZConfiguration verifies a DMZ or OPT interface is configured.
func (sp *Plugin) checkDMZConfiguration(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	for _, iface := range device.Interfaces {
		if iface.Enabled && isDMZOrOPTInterface(iface.Name) {
			return checkResult{Result: true, Known: true}
		}
	}

	return checkResult{Result: false, Known: true}
}

// checkAntiSpoofing verifies WAN interfaces have BlockPrivate and BlockBogons enabled.
func (sp *Plugin) checkAntiSpoofing(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	hasWAN := false
	for _, iface := range device.Interfaces {
		if !iface.Enabled || !isWANInterface(iface.Name) {
			continue
		}
		hasWAN = true
		if !iface.BlockPrivate || !iface.BlockBogons {
			return checkResult{Result: false, Known: true}
		}
	}

	if !hasWAN {
		return unknown
	}

	return checkResult{Result: true, Known: true}
}

// checkSourceRouting verifies sysctl settings disable IP source routing.
func (sp *Plugin) checkSourceRouting(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	if len(device.Sysctl) == 0 {
		return unknown
	}

	sourceRouteFound := false
	acceptSourceRouteFound := false
	sourceRouteDisabled := false
	acceptSourceRouteDisabled := false

	for _, item := range device.Sysctl {
		switch item.Tunable {
		case "net.inet.ip.sourceroute":
			sourceRouteFound = true
			sourceRouteDisabled = item.Value == "0"
		case "net.inet.ip.accept_sourceroute":
			acceptSourceRouteFound = true
			acceptSourceRouteDisabled = item.Value == "0"
		}
	}

	// If neither tunable is found, we cannot evaluate.
	if !sourceRouteFound && !acceptSourceRouteFound {
		return unknown
	}

	// Both must be found and set to 0 for full compliance.
	result := sourceRouteFound && acceptSourceRouteFound &&
		sourceRouteDisabled && acceptSourceRouteDisabled

	return checkResult{Result: result, Known: true}
}

// checkDangerousPorts checks whether any WAN pass rules allow dangerous ports.
// Returns true (Result) if dangerous ports ARE allowed — callers emit a finding
// when Result is true.
func (sp *Plugin) checkDangerousPorts(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	for _, r := range enabledPassRules(device) {
		if !ruleAppliesToWAN(r) {
			continue
		}
		if portMatchesDangerous(r.Destination.Port) || portMatchesDangerous(r.Source.Port) {
			return checkResult{Result: true, Known: true}
		}
	}

	return checkResult{Result: false, Known: true}
}

// checkSecureRemoteAccess verifies SSH is enabled and no telnet pass rules exist.
func (sp *Plugin) checkSecureRemoteAccess(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	if !device.System.SSH.Enabled {
		return checkResult{Result: false, Known: true}
	}

	// Check for telnet pass rules (port 23).
	for _, r := range enabledPassRules(device) {
		if r.Destination.Port == "23" {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkFTPIsolation checks whether FTP inbound NAT rules route to DMZ interfaces.
// This is a PARTIAL check.
func (sp *Plugin) checkFTPIsolation(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	hasFTPRules := false
	for _, r := range device.NAT.InboundRules {
		if r.Disabled {
			continue
		}
		// FTP uses ports 20-21.
		if r.Destination.Port == "21" || r.Destination.Port == "20" ||
			r.Destination.Port == "20-21" || r.ExternalPort == "21" ||
			r.ExternalPort == "20" || r.ExternalPort == "20-21" {
			hasFTPRules = true
			// Check if the rule routes to a DMZ interface.
			if slices.ContainsFunc(r.Interfaces, isDMZOrOPTInterface) {
				return checkResult{Result: true, Known: true}
			}
		}
	}

	if !hasFTPRules {
		return unknown
	}

	return checkResult{Result: false, Known: true}
}

// checkMailRestriction verifies SMTP pass rules target specific destination IPs
// rather than "any".
func (sp *Plugin) checkMailRestriction(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	hasSMTPRules := false
	for _, r := range enabledPassRules(device) {
		if r.Destination.Port == "25" || r.Destination.Port == "587" ||
			r.Destination.Port == "465" {
			hasSMTPRules = true
			if r.Destination.Address == constants.NetworkAny {
				return checkResult{Result: false, Known: true}
			}
		}
	}

	if !hasSMTPRules {
		return unknown
	}

	return checkResult{Result: true, Known: true}
}

// checkICMPFiltering checks whether ICMP pass rules exist on WAN interfaces.
// Returns true (Result) if ICMP IS allowed on WAN — callers emit a finding
// when Result is true.
func (sp *Plugin) checkICMPFiltering(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	for _, r := range enabledPassRules(device) {
		if strings.EqualFold(r.Protocol, "icmp") && ruleAppliesToWAN(r) {
			return checkResult{Result: true, Known: true}
		}
	}

	return checkResult{Result: false, Known: true}
}

// checkNATMasquerading verifies outbound NAT is enabled.
func (sp *Plugin) checkNATMasquerading(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	mode := device.NAT.OutboundMode
	if mode == "" || mode == common.OutboundDisabled {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: true, Known: true}
}

// checkDNSZoneTransfer checks whether TCP port 53 is unrestricted on WAN.
// Returns true (Result) if unrestricted TCP 53 IS found — callers emit a
// finding when Result is true.
func (sp *Plugin) checkDNSZoneTransfer(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	for _, r := range enabledPassRules(device) {
		if !ruleAppliesToWAN(r) {
			continue
		}
		if !strings.EqualFold(r.Protocol, "tcp") {
			continue
		}
		if r.Destination.Port == "53" &&
			r.Source.Address == constants.NetworkAny {
			return checkResult{Result: true, Known: true}
		}
	}

	return checkResult{Result: false, Known: true}
}

// checkEgressFiltering verifies outbound pass rules restrict their source
// addresses (not "any").
func (sp *Plugin) checkEgressFiltering(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	hasOutbound := false
	for _, r := range enabledPassRules(device) {
		if r.Direction != common.DirectionOut {
			continue
		}
		hasOutbound = true
		if r.Source.Address == constants.NetworkAny {
			return checkResult{Result: false, Known: true}
		}
	}

	if !hasOutbound {
		return unknown
	}

	return checkResult{Result: true, Known: true}
}

// checkCriticalServerProtection verifies WAN-to-LAN deny rules exist.
// This is a PARTIAL check — it confirms presence of protective rules.
func (sp *Plugin) checkCriticalServerProtection(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	for _, r := range device.FirewallRules {
		if r.Disabled {
			continue
		}
		if r.Type != common.RuleTypeBlock && r.Type != common.RuleTypeReject {
			continue
		}
		if ruleAppliesToWAN(r) {
			return checkResult{Result: true, Known: true}
		}
	}

	return checkResult{Result: false, Known: true}
}

// checkDefaultCredentials checks for active default user accounts.
// Returns true (Result) if default accounts ARE active — callers emit a
// finding when Result is true.
func (sp *Plugin) checkDefaultCredentials(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	if len(device.Users) == 0 {
		return unknown
	}

	for _, user := range device.Users {
		if user.Disabled {
			continue
		}
		nameLower := strings.ToLower(user.Name)
		if slices.Contains(defaultUsernames, nameLower) {
			return checkResult{Result: true, Known: true}
		}
	}

	return checkResult{Result: false, Known: true}
}

// checkTCPStateEnforcement verifies all TCP pass rules have a StateType set.
func (sp *Plugin) checkTCPStateEnforcement(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	hasTCPPass := false
	for _, r := range enabledPassRules(device) {
		if !strings.EqualFold(r.Protocol, "tcp") {
			continue
		}
		hasTCPPass = true
		if strings.TrimSpace(r.StateType) == "" {
			return checkResult{Result: false, Known: true}
		}
	}

	if !hasTCPPass {
		return unknown
	}

	return checkResult{Result: true, Known: true}
}

// checkFirewallHA verifies CARP/pfsync high availability is configured.
func (sp *Plugin) checkFirewallHA(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	ha := device.HighAvailability
	hasHA := ha.PfsyncPeerIP != "" || ha.SynchronizeToIP != ""
	return checkResult{Result: hasHA, Known: true}
}
