package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanObservations_NilDevice covers the nil-safety contract shared by
// the rest of the analysis package.
func TestScanObservations_NilDevice(t *testing.T) {
	t.Parallel()

	assert.Nil(t, analysis.ScanObservations(nil))
}

// TestScanObservations_PreservesExistingDetections asserts that the three
// existing DetectSecurityIssues detections (insecure WebGUI HTTP, default
// SNMP community, permissive WAN pass rule) are wrapped into Observations
// with reachability and confidence populated (U3 test scenario 1, R4).
func TestScanObservations_PreservesExistingDetections(t *testing.T) {
	t.Parallel()

	cfg := &common.CommonDevice{
		System: common.System{
			WebGUI: common.WebGUI{Protocol: "http"},
		},
		SNMP: common.SNMPConfig{ROCommunity: "public"},
		FirewallRules: []common.FirewallRule{
			{
				Type:       common.RuleTypePass,
				Interfaces: []string{"wan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
		},
	}

	observations := analysis.ScanObservations(cfg)

	byTitle := make(map[string]analysis.Observation, len(observations))
	for _, o := range observations {
		byTitle[o.Title] = o
	}

	webgui, ok := byTitle["Insecure Web GUI Protocol"]
	require.True(t, ok, "expected wrapped Insecure Web GUI Protocol observation")
	assert.Equal(t, analysis.SeverityCritical, webgui.Severity)
	assert.Equal(t, analysis.ConfidenceHigh, webgui.Confidence)
	assert.Equal(t, "system.webgui.protocol", webgui.Component)

	snmp, ok := byTitle["Default SNMP Community String"]
	require.True(t, ok, "expected wrapped Default SNMP Community String observation")
	assert.Equal(t, analysis.SeverityHigh, snmp.Severity)
	assert.Equal(t, analysis.ConfidenceHigh, snmp.Confidence)

	wanRule, ok := byTitle["Overly Permissive WAN Rule"]
	require.True(t, ok, "expected wrapped Overly Permissive WAN Rule observation")
	assert.Equal(t, analysis.SeverityHigh, wanRule.Severity)
	assert.Equal(t, analysis.WANReachable, wanRule.Reachability, "WAN pass rule finding must be tagged WAN-reachable")
	assert.Equal(t, analysis.ConfidenceHigh, wanRule.Confidence)
}

// TestDetectInsecureManagementProtocols covers the "fires on crafted config,
// silent on clean config" scenario for the insecure-management-protocols
// hygiene category.
func TestDetectInsecureManagementProtocols(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *common.CommonDevice
		wantCount int
	}{
		{
			name:      "any configured SNMP community fires, not just the default",
			cfg:       &common.CommonDevice{SNMP: common.SNMPConfig{ROCommunity: "notpublic"}},
			wantCount: 1,
		},
		{
			name:      "no SNMP community configured stays silent",
			cfg:       &common.CommonDevice{},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			observations := analysis.ScanObservations(tt.cfg)

			count := 0
			for _, o := range observations {
				if o.Component == "snmpd.protocol" {
					count++
				}
			}

			assert.Equal(t, tt.wantCount, count)
		})
	}
}

// TestDetectWeakCryptoDefaults covers the weak-crypto-defaults hygiene
// category: fires on a crafted config, stays silent on a clean one.
func TestDetectWeakCryptoDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *common.CommonDevice
		wantCount int
	}{
		{
			name:      "nil trust config stays silent",
			cfg:       &common.CommonDevice{},
			wantCount: 0,
		},
		{
			name: "clean trust config stays silent",
			cfg: &common.CommonDevice{
				Trust: &common.TrustConfig{CipherString: "ECDHE+AESGCM:ECDHE+AES256", MinProtocol: "TLSv1.2"},
			},
			wantCount: 0,
		},
		{
			name: "weak cipher token fires",
			cfg: &common.CommonDevice{
				Trust: &common.TrustConfig{CipherString: "RC4-SHA:HIGH"},
			},
			wantCount: 1,
		},
		{
			name: "weak minimum protocol fires",
			cfg: &common.CommonDevice{
				Trust: &common.TrustConfig{MinProtocol: "TLSv1"},
			},
			wantCount: 1,
		},
		{
			name: "both weak cipher and weak protocol fire two observations",
			cfg: &common.CommonDevice{
				Trust: &common.TrustConfig{CipherString: "DES-CBC3-SHA", MinProtocol: "TLSv1.1"},
			},
			wantCount: 2,
		},
		{
			name: "standard hardening suffix with excluded weak classes stays silent",
			cfg: &common.CommonDevice{
				Trust: &common.TrustConfig{
					CipherString: "HIGH:!aNULL:!MD5:!RC4:!3DES:!DES:!EXPORT",
					MinProtocol:  "TLSv1.2",
				},
			},
			wantCount: 0,
		},
		{
			name: "mixed list with an actively-enabled weak selector still fires",
			cfg: &common.CommonDevice{
				Trust: &common.TrustConfig{CipherString: "HIGH:!aNULL:!MD5:RC4-SHA", MinProtocol: "TLSv1.2"},
			},
			wantCount: 1,
		},
		{
			name: "plus-prefixed reorder-only selector stays silent",
			cfg: &common.CommonDevice{
				Trust: &common.TrustConfig{CipherString: "HIGH:+RC4", MinProtocol: "TLSv1.2"},
			},
			wantCount: 0,
		},
		{
			name: "permanent-deletion selector suppresses a later plain re-mention",
			cfg: &common.CommonDevice{
				Trust: &common.TrustConfig{CipherString: "HIGH:!RC4:RC4", MinProtocol: "TLSv1.2"},
			},
			wantCount: 0,
		},
		{
			name: "suppressible-removal selector followed by re-enable still fires",
			cfg: &common.CommonDevice{
				Trust: &common.TrustConfig{CipherString: "HIGH:-RC4:RC4", MinProtocol: "TLSv1.2"},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			observations := analysis.ScanObservations(tt.cfg)

			count := 0
			for _, o := range observations {
				if o.Component == "trust.cipherstring" || o.Component == "trust.minprotocol" {
					count++
				}
			}

			assert.Equal(t, tt.wantCount, count)
		})
	}
}

// TestDetectAnyToAnyRules covers the any-to-any-rules hygiene category,
// including per-rule granularity and reachability tagging.
func TestDetectAnyToAnyRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *common.CommonDevice
		wantCount int
	}{
		{
			name:      "no rules stays silent",
			cfg:       &common.CommonDevice{},
			wantCount: 0,
		},
		{
			name: "specific rule stays silent",
			cfg: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"lan"},
						Source:      common.RuleEndpoint{Address: "any"},
						Destination: common.RuleEndpoint{Address: "192.168.1.10", Port: "443"},
						Protocol:    "tcp",
					},
				},
			},
			wantCount: 0,
		},
		{
			name: "any-to-any pass rule fires",
			cfg: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"lan"},
						Source:      common.RuleEndpoint{Address: "any"},
						Destination: common.RuleEndpoint{Address: "any"},
					},
				},
			},
			wantCount: 1,
		},
		{
			name: "disabled any-to-any rule stays silent",
			cfg: &common.CommonDevice{
				FirewallRules: []common.FirewallRule{
					{
						Type:        common.RuleTypePass,
						Interfaces:  []string{"lan"},
						Source:      common.RuleEndpoint{Address: "any"},
						Destination: common.RuleEndpoint{Address: "any"},
						Disabled:    true,
					},
				},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			observations := analysis.ScanObservations(tt.cfg)

			count := 0
			for _, o := range observations {
				if o.Title == "Any-to-Any Pass Rule" {
					count++
				}
			}

			assert.Equal(t, tt.wantCount, count)
		})
	}
}

// TestDetectDisabledLogging covers the disabled-logging hygiene category.
func TestDetectDisabledLogging(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *common.CommonDevice
		wantCount int
	}{
		{
			name:      "syslog disabled stays silent",
			cfg:       &common.CommonDevice{},
			wantCount: 0,
		},
		{
			name: "syslog enabled with filter logging stays silent",
			cfg: &common.CommonDevice{
				Syslog: common.SyslogConfig{Enabled: true, FilterLogging: true},
			},
			wantCount: 0,
		},
		{
			name: "syslog enabled without filter logging fires",
			cfg: &common.CommonDevice{
				Syslog: common.SyslogConfig{Enabled: true, FilterLogging: false},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			observations := analysis.ScanObservations(tt.cfg)

			count := 0
			for _, o := range observations {
				if o.Component == "syslog.filterlogging" {
					count++
				}
			}

			assert.Equal(t, tt.wantCount, count)
		})
	}
}

// TestScanObservations_ExportPathUnaffected pins that ComputeAnalysis (the
// export-enrichment path consumed by internal/converter/enrichment.go and
// internal/processor/analyze.go) is unaffected by the shared engine's
// additive hygiene detectors — ScanObservations is a separate code path that
// wraps, not replaces, DetectSecurityIssues (R4).
func TestScanObservations_ExportPathUnaffected(t *testing.T) {
	t.Parallel()

	cfg := &common.CommonDevice{
		SNMP:  common.SNMPConfig{ROCommunity: "notpublic"},
		Trust: &common.TrustConfig{CipherString: "RC4-SHA"},
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
		},
		Syslog: common.SyslogConfig{Enabled: true},
	}

	// The new hygiene detectors fire on this config (sanity check that the
	// fixture actually exercises them).
	observations := analysis.ScanObservations(cfg)
	assert.NotEmpty(t, observations)

	// ComputeAnalysis / DetectSecurityIssues must be unaffected: this config
	// has no insecure WebGUI, no default SNMP community, and no permissive
	// WAN rule, so DetectSecurityIssues must still report zero findings.
	analysisResult := analysis.ComputeAnalysis(cfg)
	assert.Empty(t, analysisResult.SecurityIssues)
}

// TestScanObservations_DoesNotMutateExportPath (R4) pins the no-regression
// contract for the JSON/YAML export consumers: running the shared engine over a
// config must not alter what DetectSecurityIssues returns for that same config,
// so internal/converter and internal/processor keep observing identical output.
func TestScanObservations_DoesNotMutateExportPath(t *testing.T) {
	t.Parallel()

	cfg := &common.CommonDevice{
		System: common.System{WebGUI: common.WebGUI{Protocol: "http"}},
		SNMP:   common.SNMPConfig{ROCommunity: "public"},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
			{Name: "lan", Enabled: true},
		},
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"wan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
		},
	}

	before := analysis.DetectSecurityIssues(cfg)
	require.NotEmpty(t, before, "fixture must exercise the export-path detectors")

	// Running the shared engine must not perturb the export path.
	_ = analysis.ScanObservations(cfg)

	after := analysis.DetectSecurityIssues(cfg)
	assert.Equal(t, before, after, "ScanObservations must not mutate DetectSecurityIssues output")
}
