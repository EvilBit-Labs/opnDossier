package processor

import (
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateStatistics_IDSEnabled(t *testing.T) {
	tests := []struct {
		name                       string
		ids                        *common.IDSConfig
		expectIDSEnabled           bool
		expectIDSMode              string
		expectMonitoredInterfaces  []string
		expectDetectionProfile     string
		expectLoggingEnabled       bool
		expectIDSInSecurityFeature bool
	}{
		{
			name:             "IDS disabled (nil)",
			ids:              nil,
			expectIDSEnabled: false,
			expectIDSMode:    "",
		},
		{
			name:             "IDS disabled (enabled=false)",
			ids:              makeIDs(false, false, nil, "", false, false),
			expectIDSEnabled: false,
			expectIDSMode:    "",
		},
		{
			name:                      "IDS mode (detection only)",
			ids:                       makeIDs(true, false, []string{"lan", "wan"}, "medium", true, false),
			expectIDSEnabled:          true,
			expectIDSMode:             "IDS (Detection Only)",
			expectMonitoredInterfaces: []string{"lan", "wan"},
			expectDetectionProfile:    "medium",
			expectLoggingEnabled:      true,
		},
		{
			name:                      "IPS mode (prevention)",
			ids:                       makeIDs(true, true, []string{"lan"}, "high", false, true),
			expectIDSEnabled:          true,
			expectIDSMode:             "IPS (Prevention)",
			expectMonitoredInterfaces: []string{"lan"},
			expectDetectionProfile:    "high",
			expectLoggingEnabled:      true,
		},
		{
			name:                      "IDS enabled with no logging",
			ids:                       makeIDs(true, false, []string{"wan"}, "low", false, false),
			expectIDSEnabled:          true,
			expectIDSMode:             "IDS (Detection Only)",
			expectMonitoredInterfaces: []string{"wan"},
			expectDetectionProfile:    "low",
			expectLoggingEnabled:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &common.CommonDevice{
				System: common.System{
					Hostname: "ids-test",
					Domain:   "example.com",
				},
				IDS: tt.ids,
			}

			stats := generateStatistics(cfg)
			require.NotNil(t, stats)

			assert.Equal(t, tt.expectIDSEnabled, stats.IDSEnabled, "IDSEnabled")
			assert.Equal(t, tt.expectIDSMode, stats.IDSMode, "IDSMode")

			if tt.expectIDSEnabled {
				assert.Equal(t, tt.expectMonitoredInterfaces, stats.IDSMonitoredInterfaces, "IDSMonitoredInterfaces")
				assert.Equal(t, tt.expectDetectionProfile, stats.IDSDetectionProfile, "IDSDetectionProfile")
				assert.Equal(t, tt.expectLoggingEnabled, stats.IDSLoggingEnabled, "IDSLoggingEnabled")

				// IDS/IPS should NOT appear in SecurityFeatures (avoids double-counting)
				for _, feat := range stats.SecurityFeatures {
					assert.NotContains(t, feat, "IDS", "IDS should not be in SecurityFeatures")
					assert.NotContains(t, feat, "IPS", "IPS should not be in SecurityFeatures")
					assert.NotContains(t, feat, "Suricata", "Suricata should not be in SecurityFeatures")
				}
			}
		})
	}
}

func TestCalculateSecurityScore_IDSScoring(t *testing.T) {
	tests := []struct {
		name          string
		ids           *common.IDSConfig
		https         bool
		sshGroup      string
		firewallRules int
		expectMin     int
		expectMax     int
	}{
		{
			name:          "No IDS, no other features",
			ids:           nil,
			https:         false,
			sshGroup:      "",
			firewallRules: 0,
			expectMin:     0,
			expectMax:     0,
		},
		{
			name:          "IDS only (+15)",
			ids:           makeIDs(true, false, []string{"lan"}, "medium", false, false),
			https:         false,
			sshGroup:      "",
			firewallRules: 0,
			expectMin:     15,
			expectMax:     15,
		},
		{
			name:          "IPS mode (+15 IDS + 10 IPS = 25)",
			ids:           makeIDs(true, true, []string{"lan"}, "high", false, false),
			https:         false,
			sshGroup:      "",
			firewallRules: 0,
			expectMin:     25,
			expectMax:     25,
		},
		{
			name:          "IDS + HTTPS + SSH + firewall rules",
			ids:           makeIDs(true, false, []string{"lan"}, "medium", false, false),
			https:         true,
			sshGroup:      "admins",
			firewallRules: 5,
			// SecurityFeatures: none for IDS (fixed), but HTTPS Web GUI adds 1 feature * 10 = 10
			// Firewall: +20, HTTPS: +15, SSH: +10, IDS: +15 = 70
			expectMin: 70,
			expectMax: 70,
		},
		{
			name:          "IPS + HTTPS + SSH + firewall rules",
			ids:           makeIDs(true, true, []string{"lan"}, "high", false, false),
			https:         true,
			sshGroup:      "admins",
			firewallRules: 5,
			// SecurityFeatures: HTTPS Web GUI = 1 * 10 = 10
			// Firewall: +20, HTTPS: +15, SSH: +10, IDS: +15, IPS: +10 = 80
			expectMin: 80,
			expectMax: 80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &common.CommonDevice{
				System: common.System{
					Hostname: "score-test",
					Domain:   "example.com",
				},
				IDS: tt.ids,
			}

			if tt.https {
				cfg.System.WebGUI.Protocol = "https"
			}
			cfg.System.SSH.Group = tt.sshGroup

			rules := make([]common.FirewallRule, tt.firewallRules)
			for i := range tt.firewallRules {
				rules[i] = common.FirewallRule{
					Type:       "pass",
					Interfaces: []string{"lan"},
				}
			}
			cfg.FirewallRules = rules

			stats := generateStatistics(cfg)
			require.NotNil(t, stats)

			assert.GreaterOrEqual(t, stats.Summary.SecurityScore, tt.expectMin,
				"Security score should be >= %d, got %d", tt.expectMin, stats.Summary.SecurityScore)
			assert.LessOrEqual(t, stats.Summary.SecurityScore, tt.expectMax,
				"Security score should be <= %d, got %d", tt.expectMax, stats.Summary.SecurityScore)
		})
	}
}

func TestReport_ToMarkdown_IDSSection(t *testing.T) {
	tests := []struct {
		name           string
		ids            *common.IDSConfig
		expectSection  bool
		expectContains []string
		expectAbsent   []string
	}{
		{
			name:          "No IDS - section absent",
			ids:           nil,
			expectSection: false,
			expectAbsent:  []string{"IDS/IPS Configuration"},
		},
		{
			name:          "IDS enabled - section present",
			ids:           makeIDs(true, false, []string{"lan", "wan"}, "medium", true, false),
			expectSection: true,
			expectContains: []string{
				"IDS/IPS Configuration",
				"Enabled",
				"IDS (Detection Only)",
				"lan, wan",
				"medium",
				"Logging Enabled",
			},
		},
		{
			name:          "IPS mode - section present",
			ids:           makeIDs(true, true, []string{"lan"}, "high", false, true),
			expectSection: true,
			expectContains: []string{
				"IDS/IPS Configuration",
				"IPS (Prevention)",
				"high",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &common.CommonDevice{
				System: common.System{
					Hostname: "markdown-ids-test",
					Domain:   "example.com",
				},
				IDS: tt.ids,
			}

			report := NewReport(cfg, Config{EnableStats: true})
			md := report.ToMarkdown()

			for _, expected := range tt.expectContains {
				assert.Contains(t, md, expected, "Markdown should contain %q", expected)
			}

			for _, absent := range tt.expectAbsent {
				assert.NotContains(t, md, absent, "Markdown should not contain %q", absent)
			}
		})
	}
}

func TestCalculateSecurityScore_NoDuplicateIDSCounting(t *testing.T) {
	// Build a config with IPS enabled plus other security features
	cfg := &common.CommonDevice{
		System: common.System{
			Hostname: "dedup-test",
			Domain:   "example.com",
			WebGUI:   common.WebGUI{Protocol: "https"},
		},
		Interfaces: []common.Interface{
			{
				Name:         "wan",
				Enabled:      true,
				BlockPrivate: true,
				BlockBogons:  true,
			},
			{Name: "lan", Enabled: true},
		},
		IDS: makeIDs(true, true, []string{"lan"}, "high", true, false),
		FirewallRules: []common.FirewallRule{
			{Type: "pass", Interfaces: []string{"lan"}},
		},
	}

	stats := generateStatistics(cfg)
	require.NotNil(t, stats)

	// Security features should contain: Block Private Networks, Block Bogon Networks, HTTPS Web GUI
	// but NOT IDS/IPS entries
	assert.Len(t, stats.SecurityFeatures, 3,
		"SecurityFeatures should have exactly 3 entries (no IDS/IPS), got: %v", stats.SecurityFeatures)

	// Manually compute expected score:
	// SecurityFeatures: 3 * 10 = 30
	// Firewall rules > 0: +20
	// HTTPS: +15
	// IDS: +15
	// IPS: +10
	// SSH: 0 (no group set)
	// Total: 90
	assert.Equal(t, 90, stats.Summary.SecurityScore,
		"Security score should be 90 without double-counting")

	// Verify IDS stats are still populated correctly
	assert.True(t, stats.IDSEnabled)
	assert.Equal(t, "IPS (Prevention)", stats.IDSMode)
	assert.Equal(t, []string{"lan"}, stats.IDSMonitoredInterfaces)
	assert.Equal(t, "high", stats.IDSDetectionProfile)
	assert.True(t, stats.IDSLoggingEnabled)
}

func TestReport_IDSMarkdownNotInJSON(t *testing.T) {
	// Ensure the new IDS markdown rendering doesn't affect JSON/YAML output structure
	cfg := &common.CommonDevice{
		System: common.System{
			Hostname: "format-test",
			Domain:   "example.com",
		},
		IDS: makeIDs(true, true, []string{"lan", "wan"}, "high", true, true),
	}

	report := NewReport(cfg, Config{EnableStats: true})

	// JSON should contain the IDS fields
	jsonStr, err := report.ToJSON()
	require.NoError(t, err)
	assert.Contains(t, jsonStr, `"idsEnabled": true`)
	assert.Contains(t, jsonStr, `"idsMode": "IPS (Prevention)"`)

	// YAML should contain the IDS fields
	yamlStr, err := report.ToYAML()
	require.NoError(t, err)
	assert.Contains(t, yamlStr, "idsenabled: true")

	// Markdown should contain the IDS section
	md := report.ToMarkdown()
	assert.Contains(t, md, "IDS/IPS Configuration")

	// Verify JSON doesn't contain markdown-specific rendering artifacts
	assert.NotContains(t, jsonStr, "### IDS/IPS Configuration")
	assert.NotContains(t, jsonStr, "**Status**")
}

// makeIDs is a helper that creates an IDS config with the given parameters.
func makeIDs(enabled, ips bool, interfaces []string, profile string, syslog, syslogEve bool) *common.IDSConfig {
	return &common.IDSConfig{
		Enabled:          enabled,
		IPSMode:          ips,
		Interfaces:       interfaces,
		Detect:           common.IDSDetect{Profile: profile},
		SyslogEnabled:    syslog,
		SyslogEveEnabled: syslogEve,
	}
}

func TestGenerateStatistics_IDSMarkdownRendering(t *testing.T) {
	// Verify the markdown output contains proper formatting for the IDS section
	ids := makeIDs(true, false, []string{"wan", "lan", "opt1"}, "medium", true, true)
	cfg := &common.CommonDevice{
		System: common.System{
			Hostname: "render-test",
			Domain:   "example.com",
		},
		IDS: ids,
	}

	report := NewReport(cfg, Config{EnableStats: true})
	md := report.ToMarkdown()

	// Check that the section has proper formatting
	assert.Contains(t, md, "### IDS/IPS Configuration")
	assert.Contains(t, md, "**Status**")
	assert.Contains(t, md, "**Mode**")
	assert.Contains(t, md, "**Monitored Interfaces**")
	assert.Contains(t, md, "wan, lan, opt1")
	assert.Contains(t, md, "**Detection Profile**")
	assert.Contains(t, md, "medium")
	assert.Contains(t, md, "**Logging Enabled**")

	// Verify section ordering: IDS section should come after Load Balancer / NAT
	idsIdx := strings.Index(md, "### IDS/IPS Configuration")
	statsIdx := strings.Index(md, "## Configuration Statistics")
	findingsIdx := strings.Index(md, "## Analysis Findings")
	assert.Greater(t, idsIdx, statsIdx, "IDS section should be within statistics")
	assert.Less(t, idsIdx, findingsIdx, "IDS section should come before findings")
}
