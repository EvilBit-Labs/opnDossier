// Package firewall provides a compliance plugin for firewall-specific security checks.
package firewall

import (
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// checkResult holds the outcome of a compliance check helper. When Known is
// false the Result is meaningless — the check is skipped because config.xml
// does not contain the data needed to determine compliance.
type checkResult struct {
	Result bool
	Known  bool
}

// initialFindingsCapacity is the starting capacity for the findings slice in
// RunChecks. Sized to fit the typical failure rate on a default-state device
// (~16 findings); grows automatically under heavier loads.
const initialFindingsCapacity = 16

// Plugin implements the compliance.Plugin interface for Firewall plugin.
type Plugin struct {
	controls []compliance.Control
	// severityByID maps control ID -> severity so RunChecks can look up the
	// severity for a finding without scanning the full controls slice (previous
	// behavior: O(n) per finding; now O(1)). Populated once in NewPlugin.
	severityByID map[string]string
}

// NewPlugin creates a new Firewall compliance plugin.
func NewPlugin() *Plugin {
	baseControls := []compliance.Control{
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
			Severity:    "info",
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
			Title:       "DNS Rebind Protection",
			Description: "Unbound DNS resolver should have rebind protection configured via a non-empty private-address list",
			Category:    "DNS Security",
			Severity:    "medium",
			Rationale:   "DNS rebind protection blocks responses that resolve public names to private IP ranges, mitigating DNS rebinding attacks against internal services.",
			Remediation: "Populate Unbound's private-address list under Services > Unbound DNS > Advanced.",
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
	}

	newControls := newControlDefinitions()
	controls := make([]compliance.Control, 0, len(baseControls)+len(newControls))
	controls = append(controls, baseControls...)
	controls = append(controls, newControls...)

	severityByID := make(map[string]string, len(controls))
	for _, c := range controls {
		severityByID[c.ID] = c.Severity
	}

	p := &Plugin{
		controls:     controls,
		severityByID: severityByID,
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

// RunChecks performs Firewall compliance checks against the device configuration
// in a single traversal. Returns (findings, evaluated, err).
//
// Each helper returns (result, known). When known is false the check is skipped
// because the data needed to determine compliance is not available in config.xml,
// and that control ID is excluded from the evaluated slice. When known is true
// the control ID is appended to evaluated regardless of pass/fail.
//
// err is currently always nil — reserved for unrecoverable future conditions.
//
//nolint:gocritic,funlen // nonamedreturns enforced project-wide; length is dominated by the declarative baseEntries control table.
func (fp *Plugin) RunChecks(
	device *common.CommonDevice,
) ([]compliance.Finding, []string, error) {
	findings := make([]compliance.Finding, 0, initialFindingsCapacity)
	evaluated := make([]string, 0, len(fp.controls))

	// Inline base-control dispatch. Each entry runs exactly once and contributes
	// to both findings (on fail) and evaluated (on Known=true).
	baseEntries := []struct {
		controlID      string
		checkFn        func(*common.CommonDevice) checkResult
		failOnTrue     bool
		title          string
		description    string
		recommendation string
		component      string
		tags           []string
	}{
		{
			controlID:      "FIREWALL-001",
			checkFn:        fp.hasSSHBanner,
			title:          "SSH Warning Banner Not Configured",
			description:    "SSH warning banner is not configured",
			recommendation: "Configure SSH warning banner in /etc/ssh/sshd_config",
			component:      "ssh-config",
			tags:           []string{"ssh-security", "banner", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-002",
			checkFn:        fp.hasAutoConfigBackup,
			title:          "Auto Configuration Backup Disabled",
			description:    "Automatic configuration backup is not enabled",
			recommendation: "Enable AutoConfigBackup in Services > Auto Config Backup",
			component:      "backup-config",
			tags:           []string{"backup", "configuration", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-003",
			checkFn:        fp.hasCustomMOTD,
			title:          "Custom MOTD Not Configured",
			description:    "Message of the Day is not customized",
			recommendation: "Configure custom MOTD in /etc/motd",
			component:      "motd-config",
			tags:           []string{"motd", "legal-notice", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-004",
			checkFn:        fp.hasCustomHostname,
			title:          "Default Hostname in Use",
			description:    "Device is using default hostname",
			recommendation: "Set custom hostname in System > General Setup",
			component:      "hostname-config",
			tags:           []string{"hostname", "asset-identification", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-005",
			checkFn:        fp.hasDNSServers,
			title:          "DNS Servers Not Configured",
			description:    "DNS servers are not explicitly configured",
			recommendation: "Configure DNS servers in System > General Setup",
			component:      "dns-config",
			tags:           []string{"dns", "network-config", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-006",
			checkFn:        fp.hasIPv6Enabled,
			failOnTrue:     true,
			title:          "IPv6 Enabled",
			description:    "IPv6 is enabled and should be disabled if not required",
			recommendation: "Disable IPv6 in System > Advanced > Networking if not required",
			component:      "ipv6-config",
			tags:           []string{"ipv6", "attack-surface", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-007",
			checkFn:        fp.hasDNSRebindProtection,
			title:          "DNS Rebind Protection Missing",
			description:    "Unbound is active but has no private-address entries; DNS rebinding attacks are not mitigated.",
			recommendation: "Populate Unbound's private-address list under Services > Unbound DNS > Advanced.",
			component:      "dns-config",
			tags:           []string{"dns-rebind", "security", "firewall-controls"},
		},
		{
			controlID:      "FIREWALL-008",
			checkFn:        fp.hasHTTPSManagement,
			title:          "HTTP Management Access",
			description:    "Web management is not configured for HTTPS",
			recommendation: "Configure HTTPS in System > Advanced > Admin Access",
			component:      "management-access",
			tags:           []string{"https", "encryption", "firewall-controls"},
		},
	}

	for _, entry := range baseEntries {
		cr := entry.checkFn(device)
		if !cr.Known {
			continue
		}

		evaluated = append(evaluated, entry.controlID)

		failed := !cr.Result
		if entry.failOnTrue {
			failed = cr.Result
		}

		if !failed {
			continue
		}

		findings = append(findings, compliance.Finding{
			Type:           "compliance",
			Severity:       fp.severityByID[entry.controlID],
			Title:          entry.title,
			Description:    entry.description,
			Recommendation: entry.recommendation,
			Component:      entry.component,
			Reference:      entry.controlID,
			References:     []string{entry.controlID},
			Tags:           entry.tags,
		})
	}

	// Run new checks (FIREWALL-009 through -061) via table-driven dispatch.
	newFindings, newEvaluated := fp.runNewChecks(device)
	findings = append(findings, newFindings...)
	evaluated = append(evaluated, newEvaluated...)

	// Run inventory checks (FIREWALL-062+) — Type: "inventory", excluded from
	// compliance map. Inventory controls are NOT appended to evaluated because
	// they are informational and do not participate in compliance pass/fail.
	findings = append(findings, fp.runInventoryChecks(device)...)

	return findings, evaluated, nil
}

// GetControls returns all Firewall controls. The returned slice is a deep copy to
// prevent callers from mutating the plugin's internal state, including nested
// reference types (References, Tags, Metadata).
func (fp *Plugin) GetControls() []compliance.Control {
	return compliance.CloneControls(fp.controls)
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

// controlSeverity returns the severity for a control ID from the pre-built
// severityByID map populated in NewPlugin. Returns "" when the ID is unknown.
// O(1) — replaces the historical O(n) linear scan over fp.controls.
func (fp *Plugin) controlSeverity(id string) string {
	return fp.severityByID[id]
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

	for plugin := range strings.SplitSeq(device.System.Firmware.Plugins, ",") {
		if strings.EqualFold(strings.TrimSpace(plugin), autoConfigBackupPackage) {
			return checkResult{Result: true, Known: true}
		}
	}

	return checkResult{Result: false, Known: true}
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

// hasDNSRebindProtection checks whether Unbound DNS rebind protection is
// configured. Returns Known=true only when Unbound is active AND the MVC
// <privateaddress> element was present in config.xml — otherwise returns
// Unknown so the control is not evaluated against:
//   - nil devices (pipeline error)
//   - non-Unbound configurations (DNSMasq-only installs)
//   - installs where the MVC advanced block was never configured
//     (common on older OPNsense or minimal setups)
//
// When the check runs, Result=true iff the private-address list has at least
// one entry; Result=false means the operator explicitly cleared the list and
// rebind protection is not in force.
func (fp *Plugin) hasDNSRebindProtection(device *common.CommonDevice) checkResult {
	if device == nil {
		return unknown
	}

	if !device.DNS.Unbound.Enabled {
		return unknown
	}

	if !device.DNS.Unbound.PrivateAddressConfigured {
		return unknown
	}

	return checkResult{
		Result: len(device.DNS.Unbound.PrivateAddress) > 0,
		Known:  true,
	}
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
