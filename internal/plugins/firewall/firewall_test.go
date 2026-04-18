package firewall_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// totalControls is the expected number of controls in the firewall plugin.
const totalControls = 63

func TestFirewallPlugin_RunChecks(t *testing.T) {
	firewallPlugin := firewall.NewPlugin()

	tests := []struct {
		name               string
		config             *common.CommonDevice
		expectedFindingIDs []string
		description        string
	}{
		{
			name: "Default configuration - verifiable findings expected",
			config: &common.CommonDevice{
				System: common.System{
					Hostname: "OPNsense", // Default hostname
					Domain:   "localdomain",
					WebGUI: common.WebGUI{
						Protocol: "http", // Insecure HTTP
					},
					IPv6Allow: true, // IPv6 enabled
				},
			},
			expectedFindingIDs: []string{
				"FIREWALL-002", "FIREWALL-004", "FIREWALL-005",
				"FIREWALL-006", "FIREWALL-008",
				// New controls triggered by default config:
				"FIREWALL-014", // Console menu not disabled
				"FIREWALL-021", // No group-based privileges
				"FIREWALL-032", // No VLANs
				"FIREWALL-036", // No web GUI cert
				"FIREWALL-039", // No remote syslog
				"FIREWALL-040", // No auth logging
				"FIREWALL-041", // No filter logging
				"FIREWALL-042", // No log retention
				"FIREWALL-043", // No NTP servers
				"FIREWALL-044", // No timezone
				"FIREWALL-056", // NAT reflection not disabled
				"FIREWALL-058", // No DNSSEC
			},
			description: "Default OPNsense config triggers verifiable firewall compliance checks",
		},
		{
			name: "Custom secure configuration - minimal findings",
			config: &common.CommonDevice{
				System: common.System{
					Hostname:           "secure-firewall",
					Domain:             "company.local",
					WebGUI:             common.WebGUI{Protocol: "https", SSLCertRef: "cert-123"},
					IPv6Allow:          false, // IPv6 disabled
					DNSServers:         []string{"8.8.8.8"},
					DisableConsoleMenu: true,
					Timezone:           "America/New_York",
					TimeServers:        []string{"0.pool.ntp.org", "1.pool.ntp.org"},
				},
				Groups: []common.Group{
					{Name: "admins", Privileges: "page-system-config"},
				},
				VLANs: []common.VLAN{{Tag: "100"}},
				Syslog: common.SyslogConfig{
					Enabled:       true,
					RemoteServer:  "10.0.0.1",
					AuthLogging:   true,
					FilterLogging: true,
					LogFileSize:   "10240",
				},
				NAT: common.NATConfig{
					ReflectionDisabled: true,
					OutboundMode:       common.OutboundHybrid,
				},
				DNS: common.DNSConfig{
					Unbound: common.UnboundConfig{
						Enabled:        true,
						DNSSEC:         true,
						PrivateAddress: []string{"192.168.0.0/16", "10.0.0.0/8"},
					},
				},
			},
			expectedFindingIDs: []string{
				"FIREWALL-002", // Still no auto-backup
			},
			description: "Secure config with all new checks passing",
		},
		{
			name: "Empty configuration - verifiable findings expected",
			config: &common.CommonDevice{
				System: common.System{},
			},
			expectedFindingIDs: []string{
				"FIREWALL-002", "FIREWALL-004", "FIREWALL-005",
				"FIREWALL-008",
				// New controls triggered by empty config:
				"FIREWALL-014", // Console menu not disabled
				"FIREWALL-021", // No group-based privileges
				"FIREWALL-032", // No VLANs
				"FIREWALL-036", // No web GUI cert
				"FIREWALL-039", // No remote syslog
				"FIREWALL-040", // No auth logging
				"FIREWALL-041", // No filter logging
				"FIREWALL-042", // No log retention
				"FIREWALL-043", // No NTP servers
				"FIREWALL-044", // No timezone
				"FIREWALL-056", // NAT reflection not disabled
				"FIREWALL-058", // No DNSSEC
			},
			description: "Empty system config triggers verifiable checks (IPv6 defaults to false)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := firewallPlugin.RunChecks(tt.config)

			assert.Len(t, findings, len(tt.expectedFindingIDs), "Expected %d findings, got %d: %v",
				len(tt.expectedFindingIDs), len(findings), getFindings(findings))

			for _, expectedID := range tt.expectedFindingIDs {
				found := false
				for _, finding := range findings {
					if finding.Reference == expectedID {
						found = true

						break
					}
				}
				assert.True(t, found, "Expected finding ID %s not found in results", expectedID)
			}

			for _, finding := range findings {
				assert.NotEmpty(t, finding.Type, "Finding should have a type")
				assert.NotEmpty(t, finding.Title, "Finding should have a title")
				assert.NotEmpty(t, finding.Description, "Finding should have a description")
				assert.NotEmpty(t, finding.Recommendation, "Finding should have a recommendation")
				assert.NotEmpty(t, finding.Component, "Finding should have a component")
				assert.NotEmpty(t, finding.Reference, "Finding should have a reference")
				assert.NotEmpty(t, finding.References, "Finding should have references")
				assert.NotEmpty(t, finding.Tags, "Finding should have tags")
			}
		})
	}
}

func TestFirewallPlugin_RunChecks_NilDevice(t *testing.T) {
	firewallPlugin := firewall.NewPlugin()
	findings := firewallPlugin.RunChecks(nil)

	// Nil device produces findings for verifiable checks where nil means "not configured".
	// FIREWALL-056 (NAT reflection) returns true for nil (safe default) so no finding.
	expectedIDs := []string{
		"FIREWALL-002", "FIREWALL-004", "FIREWALL-005", "FIREWALL-008",
		// New controls that produce findings for nil device:
		"FIREWALL-014", // Console menu not disabled
		"FIREWALL-021", // No group-based privileges
		"FIREWALL-032", // No VLANs
		"FIREWALL-036", // No web GUI cert
		"FIREWALL-039", // No remote syslog
		"FIREWALL-040", // No auth logging
		"FIREWALL-041", // No filter logging
		"FIREWALL-042", // No log retention
		"FIREWALL-043", // No NTP servers
		"FIREWALL-044", // No timezone
		"FIREWALL-058", // No DNSSEC
	}
	assert.Len(t, findings, len(expectedIDs), "Nil device should produce %d findings, got %d: %v",
		len(expectedIDs), len(findings), getFindings(findings))

	for _, expectedID := range expectedIDs {
		found := false
		for _, finding := range findings {
			if finding.Reference == expectedID {
				found = true

				break
			}
		}
		assert.True(t, found, "Expected finding ID %s not found for nil device", expectedID)
	}
}

func TestFirewallPlugin_RunChecks_AutoConfigBackup(t *testing.T) {
	firewallPlugin := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
		description   string
	}{
		{
			name: "os-acb package installed - no finding",
			config: &common.CommonDevice{
				Packages: []common.Package{
					{Name: "os-acb", Installed: true},
				},
			},
			expectFinding: false,
			description:   "Auto config backup package is installed",
		},
		{
			name: "os-acb package present but not installed - finding expected",
			config: &common.CommonDevice{
				Packages: []common.Package{
					{Name: "os-acb", Installed: false},
				},
			},
			expectFinding: true,
			description:   "Auto config backup package is available but not installed",
		},
		{
			name: "os-acb in firmware plugins - no finding",
			config: &common.CommonDevice{
				System: common.System{
					Firmware: common.Firmware{
						Plugins: "os-firewall,os-acb,os-theme-cicada",
					},
				},
			},
			expectFinding: false,
			description:   "Auto config backup detected via firmware plugins string",
		},
		{
			name: "os-acb in firmware plugins case insensitive - no finding",
			config: &common.CommonDevice{
				System: common.System{
					Firmware: common.Firmware{
						Plugins: "os-firewall,OS-ACB,os-theme-cicada",
					},
				},
			},
			expectFinding: false,
			description:   "Case-insensitive match on firmware plugins string",
		},
		{
			name: "similar plugin name is not a false positive - finding expected",
			config: &common.CommonDevice{
				System: common.System{
					Firmware: common.Firmware{
						Plugins: "os-firewall,os-acb-extended,os-theme-cicada",
					},
				},
			},
			expectFinding: true,
			description:   "Substring 'os-acb-extended' must not match 'os-acb'",
		},
		{
			name: "os-acb with surrounding whitespace - no finding",
			config: &common.CommonDevice{
				System: common.System{
					Firmware: common.Firmware{
						Plugins: "os-firewall, os-acb , os-theme-cicada",
					},
				},
			},
			expectFinding: false,
			description:   "Whitespace around plugin name is trimmed before comparison",
		},
		{
			name: "no packages or firmware plugins - finding expected",
			config: &common.CommonDevice{
				System: common.System{},
			},
			expectFinding: true,
			description:   "No auto config backup detected anywhere",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := firewallPlugin.RunChecks(tt.config)
			found := false
			for _, finding := range findings {
				if finding.Reference == "FIREWALL-002" {
					found = true

					break
				}
			}
			assert.Equal(t, tt.expectFinding, found,
				"FIREWALL-002 finding presence mismatch: %s", tt.description)
		})
	}
}

func TestFirewallPlugin_RunChecks_CustomHostname(t *testing.T) {
	firewallPlugin := firewall.NewPlugin()

	tests := []struct {
		name          string
		hostname      string
		expectFinding bool
		description   string
	}{
		{
			name:          "Default OPNsense hostname",
			hostname:      "OPNsense",
			expectFinding: true,
			description:   "Default OPNsense hostname should trigger finding",
		},
		{
			name:          "Default pfSense hostname",
			hostname:      "pfSense",
			expectFinding: true,
			description:   "Default pfSense hostname should trigger finding",
		},
		{
			name:          "Default firewall hostname",
			hostname:      "firewall",
			expectFinding: true,
			description:   "Generic 'firewall' hostname should trigger finding",
		},
		{
			name:          "Default localhost hostname",
			hostname:      "localhost",
			expectFinding: true,
			description:   "localhost hostname should trigger finding",
		},
		{
			name:          "Empty hostname",
			hostname:      "",
			expectFinding: true,
			description:   "Empty hostname should trigger finding",
		},
		{
			name:          "Custom hostname",
			hostname:      "corp-fw-01",
			expectFinding: false,
			description:   "Custom hostname should not trigger finding",
		},
		{
			name:          "Case insensitive default check",
			hostname:      "OPNSENSE",
			expectFinding: true,
			description:   "Case-insensitive match against default hostnames",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &common.CommonDevice{
				System: common.System{
					Hostname: tt.hostname,
				},
			}
			findings := firewallPlugin.RunChecks(config)
			found := false
			for _, finding := range findings {
				if finding.Reference == "FIREWALL-004" {
					found = true

					break
				}
			}
			assert.Equal(t, tt.expectFinding, found,
				"FIREWALL-004 finding presence mismatch for hostname %q: %s",
				tt.hostname, tt.description)
		})
	}
}

func TestFirewallPlugin_Metadata(t *testing.T) {
	tests := []struct {
		name     string
		plugin   *firewall.Plugin
		expected string
	}{
		{
			name:     "Plugin name",
			plugin:   firewall.NewPlugin(),
			expected: "firewall",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.plugin.Name()
			assert.Equal(t, tt.expected, result)
		})
	}

	// Test version
	firewallPlugin := firewall.NewPlugin()
	assert.Equal(t, "1.0.0", firewallPlugin.Version())
	assert.NotEmpty(t, firewallPlugin.Description())
}

func TestFirewallPlugin_Controls(t *testing.T) {
	firewallPlugin := firewall.NewPlugin()

	tests := []struct {
		name             string
		controlID        string
		expectFound      bool
		expectedSeverity string
		expectedCategory string
	}{
		{
			name:             "SSH Warning Banner control",
			controlID:        "FIREWALL-001",
			expectFound:      true,
			expectedSeverity: "medium",
			expectedCategory: "SSH Security",
		},
		{
			name:             "HTTPS Web Management control",
			controlID:        "FIREWALL-008",
			expectFound:      true,
			expectedSeverity: "high",
			expectedCategory: "Management Access",
		},
		{
			name:             "Default Credential Reset control",
			controlID:        "FIREWALL-016",
			expectFound:      true,
			expectedSeverity: "critical",
			expectedCategory: "Authentication",
		},
		{
			name:             "No Any-Any Pass Rules control",
			controlID:        "FIREWALL-022",
			expectFound:      true,
			expectedSeverity: "high",
			expectedCategory: "Firewall Rule Hygiene",
		},
		{
			name:             "Strong VPN Encryption control",
			controlID:        "FIREWALL-047",
			expectFound:      true,
			expectedSeverity: "high",
			expectedCategory: "VPN Configuration",
		},
		{
			name:             "HA Configuration control",
			controlID:        "FIREWALL-061",
			expectFound:      true,
			expectedSeverity: "medium",
			expectedCategory: "High Availability",
		},
		{
			name:        "Non-existent control",
			controlID:   "FIREWALL-999",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control, err := firewallPlugin.GetControlByID(tt.controlID)

			if tt.expectFound {
				require.NoError(t, err)
				require.NotNil(t, control)
				assert.Equal(t, tt.controlID, control.ID)
				assert.Equal(t, tt.expectedSeverity, control.Severity)
				assert.Equal(t, tt.expectedCategory, control.Category)
				assert.NotEmpty(t, control.Title)
				assert.NotEmpty(t, control.Description)
				assert.NotEmpty(t, control.Rationale)
				assert.NotEmpty(t, control.Remediation)
				assert.NotEmpty(t, control.Tags)
			} else {
				require.Error(t, err)
				assert.Nil(t, control)
			}
		})
	}

	// Test GetControls returns all controls
	controls := firewallPlugin.GetControls()
	assert.Len(t, controls, totalControls, "Expected %d firewall controls", totalControls)

	// Verify all control IDs are unique
	controlIDs := make(map[string]bool)
	for _, control := range controls {
		assert.False(t, controlIDs[control.ID], "Duplicate control ID: %s", control.ID)
		controlIDs[control.ID] = true
	}
}

func TestFirewallPlugin_ValidateConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		plugin      *firewall.Plugin
		expectError bool
	}{
		{
			name:        "Valid plugin configuration",
			plugin:      firewall.NewPlugin(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.plugin.ValidateConfiguration()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFirewallPlugin_FindingSeverityMatchesControl(t *testing.T) {
	t.Parallel()

	firewallPlugin := firewall.NewPlugin()

	// Build a device that triggers many verifiable findings.
	device := &common.CommonDevice{
		System: common.System{
			Hostname:  "OPNsense",
			IPv6Allow: true,
			WebGUI:    common.WebGUI{Protocol: "http"},
		},
	}

	findings := firewallPlugin.RunChecks(device)
	require.NotEmpty(t, findings, "expected at least one finding")

	for _, finding := range findings {
		control, err := firewallPlugin.GetControlByID(finding.Reference)
		require.NoError(t, err, "finding references unknown control %s", finding.Reference)
		assert.Equal(t, control.Severity, finding.Severity,
			"finding %s severity %q does not match control severity %q",
			finding.Reference, finding.Severity, control.Severity)
	}
}

// Tests for new management plane checks (FIREWALL-014 through -021).

func TestFirewallPlugin_ConsoleMenuProtection(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name:          "Console menu disabled - no finding",
			config:        &common.CommonDevice{System: common.System{DisableConsoleMenu: true}},
			expectFinding: false,
		},
		{
			name:          "Console menu enabled - finding expected",
			config:        &common.CommonDevice{System: common.System{DisableConsoleMenu: false}},
			expectFinding: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-014", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_DefaultCredentialReset(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "Default admin enabled - finding expected",
			config: &common.CommonDevice{
				Users: []common.User{{Name: "admin", Disabled: false}},
			},
			expectFinding: true,
		},
		{
			name: "Default admin disabled - no finding",
			config: &common.CommonDevice{
				Users: []common.User{{Name: "admin", Disabled: true}},
			},
			expectFinding: false,
		},
		{
			name: "Root enabled - finding expected",
			config: &common.CommonDevice{
				Users: []common.User{{Name: "root", Disabled: false}},
			},
			expectFinding: true,
		},
		{
			name: "Custom user only - no finding",
			config: &common.CommonDevice{
				Users: []common.User{{Name: "johndoe", Disabled: false}},
			},
			expectFinding: false,
		},
		{
			name: "Case insensitive admin - finding expected",
			config: &common.CommonDevice{
				Users: []common.User{{Name: "ADMIN", Disabled: false}},
			},
			expectFinding: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-016", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_LeastPrivilegeAccess(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "Group with page-all - finding expected",
			config: &common.CommonDevice{
				Groups: []common.Group{{Name: "admins", Privileges: "page-all"}},
			},
			expectFinding: true,
		},
		{
			name: "Group with specific privileges - no finding",
			config: &common.CommonDevice{
				Groups: []common.Group{{Name: "admins", Privileges: "page-system-config"}},
			},
			expectFinding: false,
		},
		{
			name: "No groups - no finding",
			config: &common.CommonDevice{
				Groups: []common.Group{},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-018", tt.expectFinding)
		})
	}
}

// Tests for rule hygiene checks (FIREWALL-022 through -035).

func TestFirewallPlugin_NoAnyAnyPassRules(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "Any-any pass rule - finding expected",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: constants.NetworkAny},
						Destination: common.RuleEndpoint{Address: constants.NetworkAny},
					},
				},
			},
			expectFinding: true,
		},
		{
			name: "Specific pass rule - no finding",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: "10.0.0.0/24"},
						Destination: common.RuleEndpoint{Address: constants.NetworkAny},
						Protocol:    "tcp",
					},
				},
			},
			expectFinding: false,
		},
		{
			name: "Disabled any-any rule ignored - no finding",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Source:      common.RuleEndpoint{Address: constants.NetworkAny},
						Destination: common.RuleEndpoint{Address: constants.NetworkAny},
						Disabled:    true,
					},
				},
			},
			expectFinding: false,
		},
		{
			name: "Block rule with any-any not counted - no finding",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypeBlock,
						Source:      common.RuleEndpoint{Address: constants.NetworkAny},
						Destination: common.RuleEndpoint{Address: constants.NetworkAny},
					},
				},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-022", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_NoAnySourceOnWANInbound(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "WAN pass rule with any source - finding expected",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:       common.RuleTypePass,
						Interfaces: []string{"wan"},
						Source:     common.RuleEndpoint{Address: constants.NetworkAny},
					},
				},
			},
			expectFinding: true,
		},
		{
			name: "WAN pass rule with specific source - no finding",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:       common.RuleTypePass,
						Interfaces: []string{"wan"},
						Source:     common.RuleEndpoint{Address: "203.0.113.0/24"},
					},
				},
			},
			expectFinding: false,
		},
		{
			name: "LAN pass rule with any source - no finding",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:       common.RuleTypePass,
						Interfaces: []string{"lan"},
						Source:     common.RuleEndpoint{Address: constants.NetworkAny},
					},
				},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-023", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_RuleDocumentation(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "Rule without description - finding expected",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{Type: common.RuleTypePass, Description: ""},
				},
			},
			expectFinding: true,
		},
		{
			name: "All rules documented - no finding",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{Type: common.RuleTypePass, Description: "Allow HTTP"},
				},
			},
			expectFinding: false,
		},
		{
			name: "Disabled rule without description ignored - no finding",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{Type: common.RuleTypePass, Description: "", Disabled: true},
				},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-025", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_PrivateAddressFilteringOnWAN(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "WAN without BlockPrivate - finding expected",
			config: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "wan", Enabled: true, BlockPrivate: false},
				},
			},
			expectFinding: true,
		},
		{
			name: "WAN with BlockPrivate - no finding",
			config: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "wan", Enabled: true, BlockPrivate: true},
				},
			},
			expectFinding: false,
		},
		{
			name: "No WAN interface - no finding (unknown)",
			config: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true},
				},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-029", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_BogonFilteringOnWAN(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "WAN without BlockBogons - finding expected",
			config: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "wan", Enabled: true, BlockBogons: false},
				},
			},
			expectFinding: true,
		},
		{
			name: "WAN with BlockBogons - no finding",
			config: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "wan", Enabled: true, BlockBogons: true},
				},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-030", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_SourceRouteRejection(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "Source routing disabled - no finding",
			config: &common.CommonDevice{
				Sysctl: []common.SysctlItem{
					{Tunable: "net.inet.ip.sourceroute", Value: "0"},
				},
			},
			expectFinding: false,
		},
		{
			name: "Source routing enabled - finding expected",
			config: &common.CommonDevice{
				Sysctl: []common.SysctlItem{
					{Tunable: "net.inet.ip.sourceroute", Value: "1"},
				},
			},
			expectFinding: true,
		},
		{
			name: "Sysctl not present - no finding (unknown)",
			config: &common.CommonDevice{
				Sysctl: []common.SysctlItem{},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-033", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_SYNFloodProtection(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "Syncookies enabled - no finding",
			config: &common.CommonDevice{
				Sysctl: []common.SysctlItem{
					{Tunable: "net.inet.tcp.syncookies", Value: "1"},
				},
			},
			expectFinding: false,
		},
		{
			name: "Syncookies disabled - finding expected",
			config: &common.CommonDevice{
				Sysctl: []common.SysctlItem{
					{Tunable: "net.inet.tcp.syncookies", Value: "0"},
				},
			},
			expectFinding: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-034", tt.expectFinding)
		})
	}
}

// Tests for encryption and monitoring checks (FIREWALL-036 through -053).

func TestFirewallPlugin_RemoteSyslog(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "Syslog enabled with remote server - no finding",
			config: &common.CommonDevice{
				Syslog: common.SyslogConfig{Enabled: true, RemoteServer: "10.0.0.1"},
			},
			expectFinding: false,
		},
		{
			name: "Syslog enabled no remote server - finding expected",
			config: &common.CommonDevice{
				Syslog: common.SyslogConfig{Enabled: true},
			},
			expectFinding: true,
		},
		{
			name: "Syslog disabled - finding expected",
			config: &common.CommonDevice{
				Syslog: common.SyslogConfig{Enabled: false},
			},
			expectFinding: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-039", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_NTPConfiguration(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "Two NTP servers - no finding",
			config: &common.CommonDevice{
				System: common.System{TimeServers: []string{"0.pool.ntp.org", "1.pool.ntp.org"}},
			},
			expectFinding: false,
		},
		{
			name: "One NTP server - finding expected",
			config: &common.CommonDevice{
				System: common.System{TimeServers: []string{"0.pool.ntp.org"}},
			},
			expectFinding: true,
		},
		{
			name:          "No NTP servers - finding expected",
			config:        &common.CommonDevice{System: common.System{}},
			expectFinding: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-043", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_SNMPChecks(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		controlID     string
		expectFinding bool
	}{
		{
			name:          "No SNMP community - 045 no finding",
			config:        &common.CommonDevice{SNMP: common.SNMPConfig{}},
			controlID:     "FIREWALL-045",
			expectFinding: false,
		},
		{
			name:          "SNMP community set - 045 finding expected",
			config:        &common.CommonDevice{SNMP: common.SNMPConfig{ROCommunity: "mycommunity"}},
			controlID:     "FIREWALL-045",
			expectFinding: true,
		},
		{
			name:          "Default community public - 046 finding expected",
			config:        &common.CommonDevice{SNMP: common.SNMPConfig{ROCommunity: "public"}},
			controlID:     "FIREWALL-046",
			expectFinding: true,
		},
		{
			name:          "Default community private - 046 finding expected",
			config:        &common.CommonDevice{SNMP: common.SNMPConfig{ROCommunity: "private"}},
			controlID:     "FIREWALL-046",
			expectFinding: true,
		},
		{
			name:          "Custom community - 046 no finding",
			config:        &common.CommonDevice{SNMP: common.SNMPConfig{ROCommunity: "s3cur3str1ng"}},
			controlID:     "FIREWALL-046",
			expectFinding: false,
		},
		{
			name:          "Empty community - 046 no finding",
			config:        &common.CommonDevice{SNMP: common.SNMPConfig{}},
			controlID:     "FIREWALL-046",
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, tt.controlID, tt.expectFinding)
		})
	}
}

// Tests for VPN checks (FIREWALL-047 through -053).

func TestFirewallPlugin_StrongVPNEncryption(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "Weak encryption 3des - finding expected",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase2Tunnels: []common.IPsecPhase2Tunnel{
						{EncryptionAlgorithms: []string{"3des"}},
					},
				}},
			},
			expectFinding: true,
		},
		{
			name: "Strong encryption aes-256-gcm - no finding",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase2Tunnels: []common.IPsecPhase2Tunnel{
						{EncryptionAlgorithms: []string{"aes-256-gcm"}},
					},
				}},
			},
			expectFinding: false,
		},
		{
			name: "No IPsec configured - no finding (unknown)",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{Enabled: false}},
			},
			expectFinding: false,
		},
		{
			name: "Disabled tunnel ignored - no finding",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase2Tunnels: []common.IPsecPhase2Tunnel{
						{EncryptionAlgorithms: []string{"des"}, Disabled: true},
					},
				}},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-047", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_StrongVPNIntegrity(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "Weak hash md5 - finding expected",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase2Tunnels: []common.IPsecPhase2Tunnel{
						{HashAlgorithms: []string{"md5"}},
					},
				}},
			},
			expectFinding: true,
		},
		{
			name: "Strong hash sha256 - no finding",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase2Tunnels: []common.IPsecPhase2Tunnel{
						{HashAlgorithms: []string{"sha256"}},
					},
				}},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-048", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_PerfectForwardSecrecy(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "PFS disabled - finding expected",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase2Tunnels: []common.IPsecPhase2Tunnel{
						{PFSGroup: "off"},
					},
				}},
			},
			expectFinding: true,
		},
		{
			name: "PFS empty - finding expected",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase2Tunnels: []common.IPsecPhase2Tunnel{
						{PFSGroup: ""},
					},
				}},
			},
			expectFinding: true,
		},
		{
			name: "PFS group 14 - no finding",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase2Tunnels: []common.IPsecPhase2Tunnel{
						{PFSGroup: "14"},
					},
				}},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-049", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_NoIKEv1AggressiveMode(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "IKEv1 aggressive - finding expected",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase1Tunnels: []common.IPsecPhase1Tunnel{
						{IKEType: "ikev1", Mode: "aggressive"},
					},
				}},
			},
			expectFinding: true,
		},
		{
			name: "IKEv1 main mode - no finding",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase1Tunnels: []common.IPsecPhase1Tunnel{
						{IKEType: "ikev1", Mode: "main"},
					},
				}},
			},
			expectFinding: false,
		},
		{
			name: "IKEv2 - no finding",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase1Tunnels: []common.IPsecPhase1Tunnel{
						{IKEType: "ikev2"},
					},
				}},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-051", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_IKEv2Preferred(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "IKEv1 in use - finding expected",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase1Tunnels: []common.IPsecPhase1Tunnel{
						{IKEType: "ikev1"},
					},
				}},
			},
			expectFinding: true,
		},
		{
			name: "IKEv2 in use - no finding",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase1Tunnels: []common.IPsecPhase1Tunnel{
						{IKEType: "ikev2"},
					},
				}},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-052", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_DeadPeerDetection(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "DPD configured - no finding",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase1Tunnels: []common.IPsecPhase1Tunnel{
						{DPDDelay: "30", DPDMaxFail: "5"},
					},
				}},
			},
			expectFinding: false,
		},
		{
			name: "DPD not configured - finding expected",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase1Tunnels: []common.IPsecPhase1Tunnel{
						{DPDDelay: ""},
					},
				}},
			},
			expectFinding: true,
		},
		{
			name: "DPD delay zero - finding expected",
			config: &common.CommonDevice{
				VPN: common.VPN{IPsec: common.IPsecConfig{
					Enabled: true,
					Phase1Tunnels: []common.IPsecPhase1Tunnel{
						{DPDDelay: "0"},
					},
				}},
			},
			expectFinding: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-053", tt.expectFinding)
		})
	}
}

// Tests for services checks (FIREWALL-054 through -061).

func TestFirewallPlugin_OutboundNATControl(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "Automatic mode - finding expected",
			config: &common.CommonDevice{
				NAT: common.NATConfig{OutboundMode: common.OutboundAutomatic},
			},
			expectFinding: true,
		},
		{
			name: "Hybrid mode - no finding",
			config: &common.CommonDevice{
				NAT: common.NATConfig{OutboundMode: common.OutboundHybrid},
			},
			expectFinding: false,
		},
		{
			name: "Advanced mode - no finding",
			config: &common.CommonDevice{
				NAT: common.NATConfig{OutboundMode: common.OutboundAdvanced},
			},
			expectFinding: false,
		},
		{
			name:          "No outbound mode - no finding (unknown)",
			config:        &common.CommonDevice{NAT: common.NATConfig{}},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-055", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_DNSSECValidation(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "DNSSEC enabled - no finding",
			config: &common.CommonDevice{
				DNS: common.DNSConfig{Unbound: common.UnboundConfig{Enabled: true, DNSSEC: true}},
			},
			expectFinding: false,
		},
		{
			name: "DNSSEC disabled - finding expected",
			config: &common.CommonDevice{
				DNS: common.DNSConfig{Unbound: common.UnboundConfig{Enabled: true, DNSSEC: false}},
			},
			expectFinding: true,
		},
		{
			name: "Unbound not enabled - finding expected",
			config: &common.CommonDevice{
				DNS: common.DNSConfig{Unbound: common.UnboundConfig{Enabled: false}},
			},
			expectFinding: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-058", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_DNSRebindCheck(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
		description   string
	}{
		{
			name: "unbound enabled with private-address list - no finding",
			config: &common.CommonDevice{
				DNS: common.DNSConfig{
					Unbound: common.UnboundConfig{
						Enabled:        true,
						PrivateAddress: []string{"192.168.0.0/16", "10.0.0.0/8"},
					},
				},
			},
			expectFinding: false,
			description:   "Rebind protection configured → compliant, no finding",
		},
		{
			name: "unbound enabled with empty private-address - finding expected",
			config: &common.CommonDevice{
				DNS: common.DNSConfig{
					Unbound: common.UnboundConfig{Enabled: true, PrivateAddress: nil},
				},
			},
			expectFinding: true,
			description:   "Unbound active but no private-address → protection missing",
		},
		{
			name: "unbound enabled with zero-length slice - finding expected",
			config: &common.CommonDevice{
				DNS: common.DNSConfig{
					Unbound: common.UnboundConfig{Enabled: true, PrivateAddress: []string{}},
				},
			},
			expectFinding: true,
			description:   "Non-nil zero-length slice is treated identically to nil",
		},
		{
			name: "unbound disabled with private-address populated - no finding (unknown)",
			config: &common.CommonDevice{
				DNS: common.DNSConfig{
					Unbound: common.UnboundConfig{
						Enabled:        false,
						PrivateAddress: []string{"192.168.0.0/16"},
					},
				},
			},
			expectFinding: false,
			description:   "Unbound off → check is Unknown (may be DNSMasq install)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-007", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_DNSRebindCheck_NilDevice(t *testing.T) {
	fp := firewall.NewPlugin()

	// Nil device: hasDNSRebindCheck returns Unknown, so no FIREWALL-007 finding fires.
	assertFindingPresence(t, fp, nil, "FIREWALL-007", false)
}

func TestFirewallPlugin_DNSRebindCheck_EvaluableWhenUnboundEnabled(t *testing.T) {
	fp := firewall.NewPlugin()

	// When Unbound is enabled, FIREWALL-007 is evaluable regardless of the
	// private-address list content — this is the positive counterpart to the
	// EvaluatedControlIDs test whose device has Unbound disabled.
	device := &common.CommonDevice{
		DNS: common.DNSConfig{
			Unbound: common.UnboundConfig{Enabled: true},
		},
	}
	assert.Contains(t, fp.EvaluatedControlIDs(device), "FIREWALL-007")
}

func TestFirewallPlugin_HAConfiguration(t *testing.T) {
	fp := firewall.NewPlugin()

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name: "HA configured with peer - no finding",
			config: &common.CommonDevice{
				HighAvailability: common.HighAvailability{
					PfsyncInterface: "sync0",
					PfsyncPeerIP:    "10.0.0.2",
					SynchronizeToIP: "10.0.0.2",
				},
			},
			expectFinding: false,
		},
		{
			name: "HA partially configured without peer - finding expected",
			config: &common.CommonDevice{
				HighAvailability: common.HighAvailability{
					PfsyncInterface: "sync0",
					SynchronizeToIP: "10.0.0.2",
				},
			},
			expectFinding: true,
		},
		{
			name: "No HA at all - no finding (unknown)",
			config: &common.CommonDevice{
				HighAvailability: common.HighAvailability{},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-061", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_DisabledRuleCleanup(t *testing.T) {
	fp := firewall.NewPlugin()

	// Create 11 disabled rules to exceed the threshold of 10.

	manyDisabled := make([]common.FirewallRule, 11)
	for i := range manyDisabled {
		manyDisabled[i] = common.FirewallRule{Disabled: true, Type: common.RuleTypePass}
	}

	tests := []struct {
		name          string
		config        *common.CommonDevice
		expectFinding bool
	}{
		{
			name:          "11 disabled rules - finding expected",
			config:        &common.CommonDevice{FirewallRules: manyDisabled},
			expectFinding: true,
		},
		{
			name: "5 disabled rules - no finding",
			config: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{Disabled: true},
					{Disabled: true},
					{Disabled: true},
					{Disabled: true},
					{Disabled: true},
				},
			},
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFindingPresence(t, fp, tt.config, "FIREWALL-026", tt.expectFinding)
		})
	}
}

func TestFirewallPlugin_EvaluatedControlIDs(t *testing.T) {
	fp := firewall.NewPlugin()

	// A device with enough data to evaluate many controls.
	device := &common.CommonDevice{
		System: common.System{
			Hostname:   "test-fw",
			WebGUI:     common.WebGUI{Protocol: "https", SSLCertRef: "cert-1"},
			DNSServers: []string{"8.8.8.8"},
		},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true, BlockPrivate: true, BlockBogons: true},
		},
		Sysctl: []common.SysctlItem{
			{Tunable: "net.inet.ip.sourceroute", Value: "0"},
			{Tunable: "net.inet.tcp.syncookies", Value: "1"},
		},
	}

	evaluated := fp.EvaluatedControlIDs(device)

	// Verify some known evaluable controls are present.
	for _, id := range []string{
		"FIREWALL-002", "FIREWALL-004", "FIREWALL-005",
		"FIREWALL-006", "FIREWALL-008",
		"FIREWALL-014", "FIREWALL-016",
		"FIREWALL-022", "FIREWALL-029", "FIREWALL-030",
		"FIREWALL-033", "FIREWALL-034",
		"FIREWALL-036", "FIREWALL-039",
	} {
		assert.Contains(t, evaluated, id, "Expected %s to be evaluable", id)
	}

	// Verify unknown controls are NOT present. FIREWALL-007 is Unknown here
	// because the test device has Unbound disabled.
	for _, id := range []string{
		"FIREWALL-001", "FIREWALL-003", "FIREWALL-007",
		"FIREWALL-009", "FIREWALL-010", "FIREWALL-011",
		"FIREWALL-012", "FIREWALL-013", "FIREWALL-015",
		"FIREWALL-019", "FIREWALL-035",
		"FIREWALL-037", "FIREWALL-038",
		"FIREWALL-057", "FIREWALL-059", "FIREWALL-060",
		// Inventory controls are intentionally excluded from compliance evaluation.
		"FIREWALL-062", "FIREWALL-063",
	} {
		assert.NotContains(t, evaluated, id, "Expected %s to be unknown/not evaluated", id)
	}
}

// assertFindingPresence is a helper that checks whether a specific control ID
// appears in the findings produced by RunChecks.
func assertFindingPresence(
	t *testing.T,
	fp *firewall.Plugin,
	config *common.CommonDevice,
	controlID string,
	expectPresent bool,
) {
	t.Helper()

	findings := fp.RunChecks(config)
	found := false

	for _, f := range findings {
		if f.Reference == controlID {
			found = true

			break
		}
	}

	assert.Equal(t, expectPresent, found,
		"%s finding presence mismatch: expected=%v actual=%v (total findings: %v)",
		controlID, expectPresent, found, getFindings(findings))
}

// Helper function to extract finding IDs for debugging.
func getFindings(findings []compliance.Finding) []string {
	var ids []string
	for _, finding := range findings {
		ids = append(ids, finding.Reference)
	}

	return ids
}
