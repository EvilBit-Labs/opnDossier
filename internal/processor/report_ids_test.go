package processor

import (
	"encoding/json"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
					Type:       common.RuleTypePass,
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
			{Type: common.RuleTypePass, Interfaces: []string{"lan"}},
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

func TestGenerateStatistics_SNMPCommunityRedacted(t *testing.T) {
	cfg := &common.CommonDevice{
		System: common.System{
			Hostname: "snmp-redact-test",
			Domain:   "example.com",
		},
		SNMP: common.SNMPConfig{
			ROCommunity: "super-secret-community",
			SysLocation: "office",
			SysContact:  "admin@example.com",
		},
	}

	stats := generateStatistics(cfg)
	require.NotNil(t, stats)

	// Find the SNMP service in ServiceDetails
	var snmpService *ServiceStatistics
	for i := range stats.ServiceDetails {
		if stats.ServiceDetails[i].Name == "SNMP Daemon" {
			snmpService = &stats.ServiceDetails[i]
			break
		}
	}
	require.NotNil(t, snmpService, "SNMP Daemon should be in ServiceDetails")

	// The community string must be redacted, not the raw value
	assert.Equal(t, "[REDACTED]", snmpService.Details["community"],
		"SNMP community string must be redacted in processor statistics")
	assert.Equal(t, "office", snmpService.Details["location"],
		"Non-sensitive SNMP details should be preserved")
	assert.Equal(t, "admin@example.com", snmpService.Details["contact"],
		"Non-sensitive SNMP details should be preserved")

	// Verify redaction in JSON statistics output
	report := NewReport(cfg, Config{EnableStats: true})
	jsonStr, err := report.ToJSON()
	require.NoError(t, err)

	// The statistics serviceDetails must contain [REDACTED], not the raw community
	assert.Contains(t, jsonStr, `"community": "[REDACTED]"`,
		"JSON statistics should contain redacted marker for SNMP community")

	// Verify redaction in Markdown output (only statistics section renders service details)
	md := report.ToMarkdown()
	assert.NotContains(t, md, "super-secret-community",
		"Markdown output must not contain raw SNMP community string")
	assert.Contains(t, md, "[REDACTED]",
		"Markdown should show redacted SNMP community")
}

func TestReport_SNMPCommunityRedactedInNormalizedConfig(t *testing.T) {
	const rawCommunity = "super-secret-community"

	cfg := &common.CommonDevice{
		System: common.System{
			Hostname: "snmp-leak-test",
			Domain:   "example.com",
		},
		SNMP: common.SNMPConfig{
			ROCommunity: rawCommunity,
			SysLocation: "rack-42",
			SysContact:  "noc@example.com",
		},
	}

	report := NewReport(cfg, Config{EnableStats: true})

	t.Run("JSON does not contain raw community", func(t *testing.T) {
		jsonStr, err := report.ToJSON()
		require.NoError(t, err)

		assert.NotContains(t, jsonStr, rawCommunity,
			"JSON output must not contain raw SNMP community string anywhere")
		assert.Contains(t, jsonStr, `"roCommunity": "[REDACTED]"`,
			"JSON normalizedConfig.snmp.roCommunity must be redacted")
		// Non-sensitive SNMP fields should still be present
		assert.Contains(t, jsonStr, "rack-42",
			"JSON should preserve non-sensitive SNMP sysLocation")
		assert.Contains(t, jsonStr, "noc@example.com",
			"JSON should preserve non-sensitive SNMP sysContact")
	})

	t.Run("YAML does not contain raw community", func(t *testing.T) {
		yamlStr, err := report.ToYAML()
		require.NoError(t, err)

		assert.NotContains(t, yamlStr, rawCommunity,
			"YAML output must not contain raw SNMP community string anywhere")
		assert.Contains(t, yamlStr, "[REDACTED]",
			"YAML normalizedConfig SNMP community must be redacted")
		// Non-sensitive SNMP fields should still be present
		assert.Contains(t, yamlStr, "rack-42",
			"YAML should preserve non-sensitive SNMP sysLocation")
		assert.Contains(t, yamlStr, "noc@example.com",
			"YAML should preserve non-sensitive SNMP sysContact")
	})

	t.Run("Markdown does not contain raw community", func(t *testing.T) {
		md := report.ToMarkdown()
		assert.NotContains(t, md, rawCommunity,
			"Markdown output must not contain raw SNMP community string")
	})

	t.Run("original device is not mutated", func(t *testing.T) {
		// Serialization must not modify the caller's CommonDevice
		assert.Equal(t, rawCommunity, cfg.SNMP.ROCommunity,
			"original CommonDevice.SNMP.ROCommunity must remain unchanged after serialization")
	})
}

// certRedactionReport is a minimal struct for unmarshalling JSON/YAML output
// to verify certificate and CA private key redaction structurally.
type certRedactionReport struct {
	NormalizedConfig struct {
		Certificates []common.Certificate          `json:"certificates" yaml:"certificates"`
		CAs          []common.CertificateAuthority `json:"cas"          yaml:"cas"`
	} `json:"normalizedConfig" yaml:"normalizedconfig"`
}

func TestReport_CertificatePrivateKeysRedacted(t *testing.T) {
	//nolint:gosec // G101: test fixture, not a real credential
	const rawPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\nSECRET\n-----END RSA PRIVATE KEY-----"

	cfg := &common.CommonDevice{
		System: common.System{
			Hostname: "cert-redact-test",
			Domain:   "example.com",
		},
		Certificates: []common.Certificate{
			{
				RefID:       "cert-001",
				Description: "web-server-cert",
				Certificate: "-----BEGIN CERTIFICATE-----\nPUBLICDATA\n-----END CERTIFICATE-----",
				PrivateKey:  rawPrivateKey,
			},
			{
				RefID:       "cert-002",
				Description: "no-key-cert",
				Certificate: "-----BEGIN CERTIFICATE-----\nOTHER\n-----END CERTIFICATE-----",
				PrivateKey:  "",
			},
		},
		CAs: []common.CertificateAuthority{
			{
				RefID:       "ca-001",
				Description: "internal-ca",
				Certificate: "-----BEGIN CERTIFICATE-----\nCAPUBLIC\n-----END CERTIFICATE-----",
				PrivateKey:  rawPrivateKey,
			},
			{
				RefID:       "ca-002",
				Description: "external-ca",
				Certificate: "-----BEGIN CERTIFICATE-----\nEXTCA\n-----END CERTIFICATE-----",
				PrivateKey:  "",
			},
		},
	}

	report := NewReport(cfg, Config{EnableStats: true})

	t.Run("JSON redaction verified structurally", func(t *testing.T) {
		jsonStr, err := report.ToJSON()
		require.NoError(t, err)

		var parsed certRedactionReport
		require.NoError(t, json.Unmarshal([]byte(jsonStr), &parsed),
			"JSON output must be valid and unmarshal into report structure")

		// Certificates: entry with key must be redacted
		require.Len(t, parsed.NormalizedConfig.Certificates, 2,
			"JSON should contain both certificates")
		assert.Equal(t, "[REDACTED]", parsed.NormalizedConfig.Certificates[0].PrivateKey,
			"cert-001 PrivateKey must be [REDACTED]")
		assert.NotEqual(t, rawPrivateKey, parsed.NormalizedConfig.Certificates[0].PrivateKey,
			"cert-001 must not contain raw private key")
		assert.Empty(t, parsed.NormalizedConfig.Certificates[1].PrivateKey,
			"cert-002 with empty key must remain empty")

		// CAs: entry with key must be redacted
		require.Len(t, parsed.NormalizedConfig.CAs, 2,
			"JSON should contain both CAs")
		assert.Equal(t, "[REDACTED]", parsed.NormalizedConfig.CAs[0].PrivateKey,
			"ca-001 PrivateKey must be [REDACTED]")
		assert.NotEqual(t, rawPrivateKey, parsed.NormalizedConfig.CAs[0].PrivateKey,
			"ca-001 must not contain raw private key")
		assert.Empty(t, parsed.NormalizedConfig.CAs[1].PrivateKey,
			"ca-002 with empty key must remain empty")

		// Non-sensitive fields preserved
		assert.Equal(t, "cert-001", parsed.NormalizedConfig.Certificates[0].RefID)
		assert.Equal(t, "web-server-cert", parsed.NormalizedConfig.Certificates[0].Description)
		assert.Contains(t, parsed.NormalizedConfig.Certificates[0].Certificate, "PUBLICDATA",
			"public certificate PEM data should be preserved")
		assert.Equal(t, "ca-001", parsed.NormalizedConfig.CAs[0].RefID)
	})

	t.Run("YAML redaction verified structurally", func(t *testing.T) {
		yamlStr, err := report.ToYAML()
		require.NoError(t, err)

		var parsed certRedactionReport
		require.NoError(t, yaml.Unmarshal([]byte(yamlStr), &parsed),
			"YAML output must be valid and unmarshal into report structure")

		// Certificates: entry with key must be redacted
		require.Len(t, parsed.NormalizedConfig.Certificates, 2,
			"YAML should contain both certificates")
		assert.Equal(t, "[REDACTED]", parsed.NormalizedConfig.Certificates[0].PrivateKey,
			"cert-001 PrivateKey must be [REDACTED]")
		assert.NotEqual(t, rawPrivateKey, parsed.NormalizedConfig.Certificates[0].PrivateKey,
			"cert-001 must not contain raw private key")
		assert.Empty(t, parsed.NormalizedConfig.Certificates[1].PrivateKey,
			"cert-002 with empty key must remain empty")

		// CAs: entry with key must be redacted
		require.Len(t, parsed.NormalizedConfig.CAs, 2,
			"YAML should contain both CAs")
		assert.Equal(t, "[REDACTED]", parsed.NormalizedConfig.CAs[0].PrivateKey,
			"ca-001 PrivateKey must be [REDACTED]")
		assert.NotEqual(t, rawPrivateKey, parsed.NormalizedConfig.CAs[0].PrivateKey,
			"ca-001 must not contain raw private key")
		assert.Empty(t, parsed.NormalizedConfig.CAs[1].PrivateKey,
			"ca-002 with empty key must remain empty")

		// Non-sensitive fields preserved
		assert.Equal(t, "web-server-cert", parsed.NormalizedConfig.Certificates[0].Description)
		assert.Equal(t, "internal-ca", parsed.NormalizedConfig.CAs[0].Description)
	})

	t.Run("original device is not mutated", func(t *testing.T) {
		assert.Equal(t, rawPrivateKey, cfg.Certificates[0].PrivateKey,
			"original Certificate.PrivateKey must remain unchanged after serialization")
		assert.Equal(t, rawPrivateKey, cfg.CAs[0].PrivateKey,
			"original CA.PrivateKey must remain unchanged after serialization")
	})
}

func TestGenerateStatistics_TotalConfigItemsUsesSharedFormula(t *testing.T) {
	cfg := &common.CommonDevice{
		System: common.System{
			Hostname: "total-items-test",
			Domain:   "example.com",
		},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
			{Name: "lan", Enabled: true},
		},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"lan"}},
		},
		Users:        []common.User{{Name: "admin", Scope: "system"}},
		Groups:       []common.Group{{Name: "admins", Scope: "system"}},
		VLANs:        []common.VLAN{{Tag: "100"}},
		Bridges:      []common.Bridge{{Members: []string{"lan"}}},
		Certificates: []common.Certificate{{Description: "test-cert"}},
		CAs:          []common.CertificateAuthority{{Description: "test-ca"}},
	}

	stats := generateStatistics(cfg)
	require.NotNil(t, stats)

	// The processor should now use the shared analysis formula which includes
	// VLANs, Bridges, Certificates, and CAs in the total.
	// 2 interfaces + 1 rule + 1 user + 1 group + 0 services + 0 gateways +
	// 0 gateway groups + 0 sysctl + 0 dhcp + 0 lb monitors +
	// 1 VLAN + 1 bridge + 1 cert + 1 CA = 9
	expectedTotal := 2 + 1 + 1 + 1 + 0 + 0 + 0 + 0 + 0 + 0 + 1 + 1 + 1 + 1
	assert.Equal(t, expectedTotal, stats.Summary.TotalConfigItems,
		"TotalConfigItems should use the shared analysis formula including VLANs/Bridges/Certs/CAs")
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
