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

// shadowScanBaseRule mirrors shadow_test.go's baseShadowRule (unexported,
// package-internal) so this external test package can build the same
// AE1-shaped fixture: a quick WAN inbound rule with every dimension
// wildcarded (interface rules default to quick under pf semantics).
func shadowScanBaseRule(ruleType common.FirewallRuleType) common.FirewallRule {
	return common.FirewallRule{
		Type:        ruleType,
		Interfaces:  []string{"wan"},
		Direction:   common.DirectionIn,
		Quick:       true,
		Source:      common.RuleEndpoint{Address: "any"},
		Destination: common.RuleEndpoint{Address: "any"},
	}
}

// TestScanObservations_IncludesShadowedRules (U8, R15, KTD-7) asserts a
// config with a firewall-rule shadow (AE1-shaped: an earlier WAN pass rule
// fully shadowing a later WAN block rule) surfaces a corresponding shadow
// Observation from ScanObservations — the blue-mode audit surfacing path
// (Consumer 3 of the one-core/three-consumer design, ADR-0004).
//
// Because the shadow is WAN-reachable and Security-class, this same
// Observation is also asserted present with Reachability == WANReachable,
// which is exactly the signal generateRedReport's WAN filter consumes to
// surface it as a red-mode attack surface (KTD-7's intended consequence — no
// red-specific code is added here, only the shared assertion that the
// producer emits a WAN-tagged observation for a WAN-reachable shadow).
func TestScanObservations_IncludesShadowedRules(t *testing.T) {
	t.Parallel()

	earlier := shadowScanBaseRule(common.RuleTypePass)
	earlier.Destination.Port = "22"

	later := shadowScanBaseRule(common.RuleTypeBlock)
	later.Source.Address = "10.0.0.0/8"
	later.Destination.Port = "22"

	cfg := &common.CommonDevice{
		Interfaces:    []common.Interface{{Name: "wan", Enabled: true}},
		FirewallRules: []common.FirewallRule{earlier, later},
	}

	observations := analysis.ScanObservations(cfg)

	var shadow *analysis.Observation
	for i := range observations {
		if observations[i].Component == "filter.rule[1]" {
			shadow = &observations[i]
			break
		}
	}

	require.NotNil(t, shadow, "expected a shadow observation for the shadowed rule at filter.rule[1]")
	assert.Equal(t, analysis.SeverityCritical, shadow.Severity, "WAN-reachable Security shadow escalates to critical")
	assert.Equal(t, analysis.ConfidenceHigh, shadow.Confidence)
	assert.Equal(
		t,
		analysis.WANReachable,
		shadow.Reachability,
		"WAN-reachable Security shadow must be tagged WAN-reachable so it also surfaces as a red-mode attack surface",
	)
	assert.Contains(t, shadow.Evidence, "filter.rule[0]", "evidence must name the shadowing (winner) rule")
	assert.NotEmpty(t, shadow.Title)
	assert.NotEmpty(t, shadow.Description)
	assert.NotEmpty(t, shadow.Recommendation)
}

// TestScanObservations_ShadowAdvisoryMarkerPassesThrough (R8, U8) pins that
// the R8 "(unconfirmed — unresolved alias)" advisory marker set by the shadow
// core survives the Observation adaptation unchanged, so blue-mode rendering
// can still distinguish an advisory (low-confidence, unresolved-alias)
// finding from a confirmed one at the same severity.
func TestScanObservations_ShadowAdvisoryMarkerPassesThrough(t *testing.T) {
	t.Parallel()

	earlier := shadowScanBaseRule(common.RuleTypePass)
	earlier.Destination.Port = "UNRESOLVABLE"
	earlier.Destination.PortRef = &common.ObjectRef{Name: "UNRESOLVABLE"}

	later := shadowScanBaseRule(common.RuleTypeBlock)
	later.Source.Address = "10.0.0.0/8"
	later.Destination.Port = "443"

	cfg := &common.CommonDevice{
		Interfaces:    []common.Interface{{Name: "wan", Enabled: true}},
		FirewallRules: []common.FirewallRule{earlier, later},
		NamedObjects:  common.NamedObjects{}, // "UNRESOLVABLE" is not registered
	}

	observations := analysis.ScanObservations(cfg)

	var shadow *analysis.Observation
	for i := range observations {
		if observations[i].Component == "filter.rule[1]" {
			shadow = &observations[i]
			break
		}
	}

	require.NotNil(t, shadow, "expected an advisory shadow observation")
	assert.Equal(t, analysis.ConfidenceLow, shadow.Confidence, "advisory findings carry low confidence")
	assert.Contains(t, shadow.Description, "(unconfirmed — unresolved alias)")
}

// TestScanObservations_NoShadows_NoObservations pins that a config with no
// overlapping firewall rules produces no shadow observations (silent on
// clean config, matching every other producer's "fires vs stays silent"
// contract).
func TestScanObservations_NoShadows_NoObservations(t *testing.T) {
	t.Parallel()

	cfg := &common.CommonDevice{
		Interfaces: []common.Interface{{Name: "wan", Enabled: true}},
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"wan"},
				Quick:       true,
				Source:      common.RuleEndpoint{Address: "192.168.1.1"},
				Destination: common.RuleEndpoint{Address: "192.168.1.2", Port: "80"},
			},
			{
				Type:        common.RuleTypeBlock,
				Interfaces:  []string{"wan"},
				Quick:       true,
				Source:      common.RuleEndpoint{Address: "10.0.0.1"},
				Destination: common.RuleEndpoint{Address: "10.0.0.2", Port: "443"},
			},
		},
	}

	observations := analysis.ScanObservations(cfg)

	for _, o := range observations {
		assert.NotContains(t, o.Title, "Shadowed Firewall Rule")
	}
}
