// Package firewall provides a compliance plugin for firewall-specific security checks.
package firewall

import (
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// checkResult holds the outcome of a compliance check helper. When Known is
// false the Result is meaningless — the check is skipped because config.xml
// does not contain the data needed to determine compliance.
type checkResult struct {
	Result bool
	Known  bool
}

// Plugin implements the compliance.Plugin interface for Firewall plugin.
type Plugin struct {
	controls []compliance.Control
}

// NewPlugin creates a new Firewall compliance plugin.
func NewPlugin() *Plugin {
	p := &Plugin{
		controls: []compliance.Control{
			{
				ID:          "FIREWALL-001",
				Title:       "SSH Warning Banner Configuration",
				Description: "SSH warning banner should be configured",
				Category:    "SSH Security",
				Severity:    "medium",
				Rationale:   "SSH warning banners provide legal notice and deter unauthorized access",
				Remediation: "Configure SSH warning banner in /etc/ssh/sshd_config with Banner /etc/issue.net",
				Tags:        []string{"ssh-security", "banner", "firewall-controls"},
			},
			{
				ID:          "FIREWALL-002",
				Title:       "Auto Configuration Backup",
				Description: "Automatic configuration backup should be enabled",
				Category:    "Backup and Recovery",
				Severity:    "medium",
				Rationale:   "Automatic backups ensure configuration can be restored in case of failure",
				Remediation: "Enable AutoConfigBackup in Services > Auto Config Backup",
				Tags:        []string{"backup", "configuration", "firewall-controls"},
			},
			{
				ID:          "FIREWALL-003",
				Title:       "Message of the Day",
				Description: "Message of the Day should be customized",
				Category:    "System Configuration",
				Severity:    "low",
				Rationale:   "Custom MOTD provides legal notice and system identification",
				Remediation: "Configure custom MOTD in /etc/motd with appropriate legal notice",
				Tags:        []string{"motd", "legal-notice", "firewall-controls"},
			},
			{
				ID:          "FIREWALL-004",
				Title:       "Hostname Configuration",
				Description: "Device hostname should be customized",
				Category:    "System Configuration",
				Severity:    "low",
				Rationale:   "Custom hostname helps with asset identification and management",
				Remediation: "Set custom hostname in System > General Setup",
				Tags:        []string{"hostname", "asset-identification", "firewall-controls"},
			},
			{
				ID:          "FIREWALL-005",
				Title:       "DNS Server Configuration",
				Description: "DNS servers should be explicitly configured",
				Category:    "Network Configuration",
				Severity:    "medium",
				Rationale:   "Explicit DNS configuration ensures reliable name resolution",
				Remediation: "Configure DNS servers in System > General Setup",
				Tags:        []string{"dns", "network-config", "firewall-controls"},
			},
			{
				ID:          "FIREWALL-006",
				Title:       "IPv6 Disablement",
				Description: "IPv6 should be disabled if not required",
				Category:    "Network Configuration",
				Severity:    "medium",
				Rationale:   "Disabling IPv6 reduces attack surface if not needed",
				Remediation: "Disable IPv6 in System > Advanced > Networking if not required",
				Tags:        []string{"ipv6", "attack-surface", "firewall-controls"},
			},
			{
				ID:          "FIREWALL-007",
				Title:       "DNS Rebind Check",
				Description: "DNS rebind check should be disabled",
				Category:    "DNS Security",
				Severity:    "low",
				Rationale:   "DNS rebind checks can interfere with legitimate DNS resolution",
				Remediation: "Disable DNS rebind check in System > Advanced",
				Tags:        []string{"dns-rebind", "security", "firewall-controls"},
			},
			{
				ID:          "FIREWALL-008",
				Title:       "HTTPS Web Management",
				Description: "Web management should use HTTPS",
				Category:    "Management Access",
				Severity:    "high",
				Rationale:   "HTTPS encrypts management traffic and prevents interception",
				Remediation: "Configure HTTPS in System > Advanced > Admin Access",
				Tags:        []string{"https", "encryption", "firewall-controls"},
			},
		},
	}

	return p
}

// Name returns the plugin name.
func (fp *Plugin) Name() string {
	return "firewall"
}

// Version returns the plugin version.
func (fp *Plugin) Version() string {
	return "1.0.0"
}

// Description returns the plugin description.
func (fp *Plugin) Description() string {
	return "Firewall-specific compliance checks for OPNsense configurations"
}

// RunChecks performs Firewall compliance checks against the device configuration.
// Each helper returns (result, known). When known is false the check is skipped
// because the data needed to determine compliance is not available in config.xml.
func (fp *Plugin) RunChecks(device *common.CommonDevice) []compliance.Finding {
	var findings []compliance.Finding

	// FIREWALL-001: SSH Warning Banner
	if cr := fp.hasSSHBanner(device); cr.Known && !cr.Result {
		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Title:          "SSH Warning Banner Not Configured",
			Description:    "SSH warning banner is not configured",
			Recommendation: "Configure SSH warning banner in /etc/ssh/sshd_config",
			Component:      "ssh-config",
			Reference:      "FIREWALL-001",
			References:     []string{"FIREWALL-001"},
			Tags:           []string{"ssh-security", "banner", "firewall-controls"},
		})
	}

	// FIREWALL-002: Auto Configuration Backup
	if cr := fp.hasAutoConfigBackup(device); cr.Known && !cr.Result {
		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Title:          "Auto Configuration Backup Disabled",
			Description:    "Automatic configuration backup is not enabled",
			Recommendation: "Enable AutoConfigBackup in Services > Auto Config Backup",
			Component:      "backup-config",
			Reference:      "FIREWALL-002",
			References:     []string{"FIREWALL-002"},
			Tags:           []string{"backup", "configuration", "firewall-controls"},
		})
	}

	// FIREWALL-003: Message of the Day
	if cr := fp.hasCustomMOTD(device); cr.Known && !cr.Result {
		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Title:          "Custom MOTD Not Configured",
			Description:    "Message of the Day is not customized",
			Recommendation: "Configure custom MOTD in /etc/motd",
			Component:      "motd-config",
			Reference:      "FIREWALL-003",
			References:     []string{"FIREWALL-003"},
			Tags:           []string{"motd", "legal-notice", "firewall-controls"},
		})
	}

	// FIREWALL-004: Hostname Configuration
	if cr := fp.hasCustomHostname(device); cr.Known && !cr.Result {
		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Title:          "Default Hostname in Use",
			Description:    "Device is using default hostname",
			Recommendation: "Set custom hostname in System > General Setup",
			Component:      "hostname-config",
			Reference:      "FIREWALL-004",
			References:     []string{"FIREWALL-004"},
			Tags:           []string{"hostname", "asset-identification", "firewall-controls"},
		})
	}

	// FIREWALL-005: DNS Server Configuration
	if cr := fp.hasDNSServers(device); cr.Known && !cr.Result {
		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Title:          "DNS Servers Not Configured",
			Description:    "DNS servers are not explicitly configured",
			Recommendation: "Configure DNS servers in System > General Setup",
			Component:      "dns-config",
			Reference:      "FIREWALL-005",
			References:     []string{"FIREWALL-005"},
			Tags:           []string{"dns", "network-config", "firewall-controls"},
		})
	}

	// FIREWALL-006: IPv6 Disablement
	if cr := fp.hasIPv6Enabled(device); cr.Known && cr.Result {
		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Title:          "IPv6 Enabled",
			Description:    "IPv6 is enabled and should be disabled if not required",
			Recommendation: "Disable IPv6 in System > Advanced > Networking if not required",
			Component:      "ipv6-config",
			Reference:      "FIREWALL-006",
			References:     []string{"FIREWALL-006"},
			Tags:           []string{"ipv6", "attack-surface", "firewall-controls"},
		})
	}

	// FIREWALL-007: DNS Rebind Check
	if cr := fp.hasDNSRebindCheck(device); cr.Known && cr.Result {
		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Title:          "DNS Rebind Check Enabled",
			Description:    "DNS rebind check is enabled and should be disabled",
			Recommendation: "Disable DNS rebind check in System > Advanced",
			Component:      "dns-config",
			Reference:      "FIREWALL-007",
			References:     []string{"FIREWALL-007"},
			Tags:           []string{"dns-rebind", "security", "firewall-controls"},
		})
	}

	// FIREWALL-008: HTTPS Web Management
	if cr := fp.hasHTTPSManagement(device); cr.Known && !cr.Result {
		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Title:          "HTTP Management Access",
			Description:    "Web management is not configured for HTTPS",
			Recommendation: "Configure HTTPS in System > Advanced > Admin Access",
			Component:      "management-access",
			Reference:      "FIREWALL-008",
			References:     []string{"FIREWALL-008"},
			Tags:           []string{"https", "encryption", "firewall-controls"},
		})
	}

	return findings
}

// GetControls returns all Firewall controls.
func (fp *Plugin) GetControls() []compliance.Control {
	return fp.controls
}

// GetControlByID returns a specific control by ID.
func (fp *Plugin) GetControlByID(id string) (*compliance.Control, error) {
	for _, control := range fp.controls {
		if control.ID == id {
			return &control, nil
		}
	}

	return nil, compliance.ErrControlNotFound
}

// ValidateConfiguration validates the plugin configuration.
func (fp *Plugin) ValidateConfiguration() error {
	if len(fp.controls) == 0 {
		return compliance.ErrNoControlsDefined
	}

	return nil
}

// defaultHostnames contains factory-default hostnames that indicate the device
// has not been customized. Comparisons are case-insensitive.
var defaultHostnames = []string{
	"opnsense",
	"pfsense",
	"firewall",
	"localhost",
}

// autoConfigBackupPackage is the OPNsense package name for automatic config backup.
const autoConfigBackupPackage = "os-acb"

// Helper methods for compliance checks.
// Each returns a checkResult. When Known is false, Result is meaningless and
// RunChecks skips the check — we never guess or report incorrect information.

// unknown is a convenience value for checks that cannot be evaluated.
var unknown = checkResult{Result: false, Known: false}

// hasSSHBanner checks whether an SSH warning banner is configured.
// SSH banners are OS-level configs (/etc/ssh/sshd_config) not present in
// config.xml, so the state cannot be determined.
func (fp *Plugin) hasSSHBanner(_ *common.CommonDevice) checkResult {
	return unknown
}

// hasAutoConfigBackup checks whether the os-acb automatic configuration backup
// package is installed, either via the Packages list or the Firmware.Plugins
// comma-separated string.
func (fp *Plugin) hasAutoConfigBackup(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	for _, pkg := range device.Packages {
		if strings.EqualFold(pkg.Name, autoConfigBackupPackage) && pkg.Installed {
			return checkResult{Result: true, Known: true}
		}
	}

	return checkResult{
		Result: strings.Contains(device.System.Firmware.Plugins, autoConfigBackupPackage),
		Known:  true,
	}
}

// hasCustomMOTD checks whether a custom Message of the Day is configured.
// MOTD is an OS-level file (/etc/motd) not present in config.xml, so the
// state cannot be determined.
func (fp *Plugin) hasCustomMOTD(_ *common.CommonDevice) checkResult {
	return unknown
}

// hasCustomHostname checks whether the device hostname has been changed from
// factory defaults. Empty hostnames or known defaults are treated as uncustomized.
func (fp *Plugin) hasCustomHostname(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	hostname := device.System.Hostname
	if hostname == "" {
		return checkResult{Result: false, Known: true}
	}

	for _, def := range defaultHostnames {
		if strings.EqualFold(hostname, def) {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// hasDNSServers checks whether explicit DNS servers are configured.
func (fp *Plugin) hasDNSServers(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: len(device.System.DNSServers) > 0, Known: true}
}

// hasIPv6Enabled checks whether IPv6 is enabled on the device.
func (fp *Plugin) hasIPv6Enabled(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: device.System.IPv6Allow, Known: true}
}

// hasDNSRebindCheck checks whether the DNS rebind check is enabled.
// The CommonDevice model does not yet expose this setting.
// TODO(#296): Implement once DNS rebind check field is added to CommonDevice.
func (fp *Plugin) hasDNSRebindCheck(_ *common.CommonDevice) checkResult {
	return unknown
}

// hasHTTPSManagement checks whether the web management interface uses HTTPS.
func (fp *Plugin) hasHTTPSManagement(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{
		Result: strings.EqualFold(device.System.WebGUI.Protocol, "https"),
		Known:  true,
	}
}
