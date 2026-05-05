package converter

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Test fixture constants. Extracted to satisfy goconst (literals appearing
// 3+ times in the same package fail lint per GOTCHAS §1.4).
const (
	testSecretValue  = "supersecret"
	testSNMPLocation = "office"
)

func TestPrepareForExport_PopulatesStatistics(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
	}

	result := prepareForExport(device, false)

	require.NotNil(t, result.Statistics, "Statistics should be populated")
	assert.Equal(t, common.DeviceTypeOPNsense, result.DeviceType, "DeviceType should default to OPNsense")
	assert.NotNil(t, result.Analysis, "Analysis should be populated")
	assert.NotNil(t, result.SecurityAssessment, "SecurityAssessment should be populated")
	assert.NotNil(t, result.PerformanceMetrics, "PerformanceMetrics should be populated")
}

func TestPrepareForExport_PreservesExistingDeviceType(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		DeviceType: common.DeviceTypePfSense,
	}

	result := prepareForExport(device, false)

	assert.Equal(t, common.DeviceTypePfSense, result.DeviceType, "Existing DeviceType should be preserved")
}

func TestPrepareForExport_PreservesExistingStatistics(t *testing.T) {
	t.Parallel()

	existing := &common.Statistics{
		TotalInterfaces: 42,
	}
	device := &common.CommonDevice{
		Statistics: existing,
	}

	result := prepareForExport(device, false)

	assert.Same(t, existing, result.Statistics, "Existing Statistics should be preserved")
	assert.Equal(t, 42, result.Statistics.TotalInterfaces)
	// Content of the pre-populated Statistics must remain unchanged after a
	// non-redact prepareForExport — proves the shallow-copy path does not
	// inadvertently mutate the caller's struct.
	assert.Equal(t, 42, device.Statistics.TotalInterfaces)
}

func TestPrepareForExport_PreservesExistingAnalysis(t *testing.T) {
	t.Parallel()

	existing := &common.Analysis{
		SecurityIssues: []common.SecurityFinding{{Issue: "pre-existing"}},
	}
	device := &common.CommonDevice{
		Analysis: existing,
	}

	result := prepareForExport(device, false)

	assert.Same(t, existing, result.Analysis, "Existing Analysis should be preserved")
}

func TestPrepareForExport_DoesNotMutateInput(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{Hostname: "original"},
	}

	result := prepareForExport(device, false)

	assert.Equal(t, common.DeviceTypeUnknown, device.DeviceType, "Original should not be mutated")
	assert.Nil(t, device.Statistics, "Original should not be mutated")
	assert.Nil(t, device.Analysis, "Original should not be mutated")
	assert.Nil(t, device.SecurityAssessment, "Original should not be mutated")
	assert.Nil(t, device.PerformanceMetrics, "Original should not be mutated")
	assert.NotSame(t, device, result, "Result should be a different pointer")
}

func TestToJSON_ContainsStatistics(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
	}

	c := NewJSONConverter()
	result, err := c.ToJSON(context.Background(), device, false)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(result), &parsed)
	require.NoError(t, err, "Result should be valid JSON")

	assert.NotNil(t, parsed["statistics"], "JSON output should contain statistics")
	assert.Equal(t, "opnsense", parsed["device_type"], "JSON output should contain device_type")
	assert.NotNil(t, parsed["securityAssessment"], "JSON output should contain securityAssessment")
	assert.NotNil(t, parsed["performanceMetrics"], "JSON output should contain performanceMetrics")
}

func TestToYAML_ContainsStatistics(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
	}

	c := NewYAMLConverter()
	result, err := c.ToYAML(context.Background(), device, false)
	require.NoError(t, err)

	var parsed map[string]any
	err = yaml.Unmarshal([]byte(result), &parsed)
	require.NoError(t, err, "Result should be valid YAML")

	assert.NotNil(t, parsed["statistics"], "YAML output should contain statistics")
	assert.Equal(t, "opnsense", parsed["device_type"], "YAML output should contain device_type")
	assert.NotNil(t, parsed["securityAssessment"], "YAML output should contain securityAssessment")
	assert.NotNil(t, parsed["performanceMetrics"], "YAML output should contain performanceMetrics")
}

func TestComputeStatistics_MinimalDevice(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{}

	stats := analysis.ComputeStatistics(device)

	require.NotNil(t, stats)
	assert.Zero(t, stats.TotalInterfaces)
	assert.Zero(t, stats.TotalFirewallRules)
	assert.NotNil(t, stats.InterfacesByType, "Maps should be initialized")
	assert.NotNil(t, stats.RulesByInterface, "Maps should be initialized")
	assert.NotNil(t, stats.EnabledServices, "Slices should be initialized")
}

func TestComputeStatistics_WithInterfaces(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Interfaces: []common.Interface{
			{
				Name:         "wan",
				Type:         "physical",
				Enabled:      true,
				IPAddress:    "10.0.0.1",
				BlockPrivate: true,
				BlockBogons:  true,
			},
			{Name: "lan", Type: "physical", Enabled: true, IPAddress: "192.168.1.1"},
			{Name: "opt1", Type: "vlan", Enabled: false},
		},
		System: common.System{
			WebGUI: common.WebGUI{Protocol: "https"},
		},
	}

	stats := analysis.ComputeStatistics(device)

	assert.Equal(t, 3, stats.TotalInterfaces)
	assert.Equal(t, 2, stats.InterfacesByType["physical"])
	assert.Equal(t, 1, stats.InterfacesByType["vlan"])
	assert.Len(t, stats.InterfaceDetails, 3)
	assert.Contains(t, stats.SecurityFeatures, "Block Private Networks")
	assert.Contains(t, stats.SecurityFeatures, "Block Bogon Networks")
	assert.Contains(t, stats.SecurityFeatures, "HTTPS Web GUI")
	assert.Positive(t, stats.Summary.SecurityScore)
}

func TestComputeAnalysis_MinimalDevice(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{}
	analysisResult := analysis.ComputeAnalysis(device)

	require.NotNil(t, analysisResult)
	assert.Empty(t, analysisResult.DeadRules)
	assert.Empty(t, analysisResult.UnusedInterfaces)
	assert.Empty(t, analysisResult.SecurityIssues)
	assert.Empty(t, analysisResult.PerformanceIssues)
	assert.Empty(t, analysisResult.ConsistencyIssues)
}

func TestComputeAnalysis_DeadRules(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypeBlock,
				Interfaces:  []string{"wan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"wan"},
				Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
		},
	}

	analysisResult := analysis.ComputeAnalysis(device)

	require.NotEmpty(t, analysisResult.DeadRules)
	assert.Equal(t, "wan", analysisResult.DeadRules[0].Interface)
	assert.Contains(t, analysisResult.DeadRules[0].Description, "unreachable")
}

func TestComputeAnalysis_DuplicateRules(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
			{
				Type:        common.RuleTypePass,
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
		},
	}

	analysisResult := analysis.ComputeAnalysis(device)

	require.NotEmpty(t, analysisResult.DeadRules)
	assert.Contains(t, analysisResult.DeadRules[0].Description, "duplicate")
}

func TestComputeAnalysis_UnusedInterfaces(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
			{Name: "opt1", Enabled: true},
		},
		FirewallRules: []common.FirewallRule{
			{Interfaces: []string{"wan"}},
		},
	}

	analysisResult := analysis.ComputeAnalysis(device)

	require.Len(t, analysisResult.UnusedInterfaces, 1)
	assert.Equal(t, "opt1", analysisResult.UnusedInterfaces[0].InterfaceName)
}

func TestComputeAnalysis_SecurityIssues(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			WebGUI: common.WebGUI{Protocol: "http"},
		},
		SNMP: common.SNMPConfig{ROCommunity: "public"},
		FirewallRules: []common.FirewallRule{
			{Type: common.RuleTypePass, Interfaces: []string{"wan"}, Source: common.RuleEndpoint{Address: "any"}},
		},
	}

	analysisResult := analysis.ComputeAnalysis(device)

	require.Len(t, analysisResult.SecurityIssues, 3)

	issues := make(map[string]bool)
	for _, si := range analysisResult.SecurityIssues {
		issues[si.Issue] = true
	}
	assert.True(t, issues["Insecure Web GUI Protocol"])
	assert.True(t, issues["Default SNMP Community String"])
	assert.True(t, issues["Overly Permissive WAN Rule"])
}

func TestComputeAnalysis_PerformanceIssues(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			DisableChecksumOffloading:     true,
			DisableSegmentationOffloading: true,
		},
	}

	analysisResult := analysis.ComputeAnalysis(device)

	require.Len(t, analysisResult.PerformanceIssues, 2)

	issues := make(map[string]bool)
	for _, pi := range analysisResult.PerformanceIssues {
		issues[pi.Issue] = true
	}
	assert.True(t, issues["Checksum Offloading Disabled"])
	assert.True(t, issues["Segmentation Offloading Disabled"])
}

func TestComputeAnalysis_ConsistencyIssues(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "lan", Enabled: true, IPAddress: "", Subnet: ""},
		},
		DHCP: []common.DHCPScope{
			{Interface: "lan", Enabled: true, Range: common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"}},
		},
		Users: []common.User{
			{Name: "admin", GroupName: "nonexistent"},
		},
	}

	analysisResult := analysis.ComputeAnalysis(device)

	require.NotEmpty(t, analysisResult.ConsistencyIssues)

	issues := make(map[string]bool)
	for _, ci := range analysisResult.ConsistencyIssues {
		issues[ci.Issue] = true
	}
	assert.True(t, issues["DHCP Enabled Without Interface IP"])
	assert.True(t, issues["User References Non-existent Group"])
}

func TestToJSON_ContainsAnalysis(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			WebGUI: common.WebGUI{Protocol: "http"},
		},
	}

	c := NewJSONConverter()
	result, err := c.ToJSON(context.Background(), device, false)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(result), &parsed)
	require.NoError(t, err, "Result should be valid JSON")

	assert.NotNil(t, parsed["analysis"], "JSON output should contain analysis")
}

func TestToYAML_ContainsAnalysis(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			WebGUI: common.WebGUI{Protocol: "http"},
		},
	}

	c := NewYAMLConverter()
	result, err := c.ToYAML(context.Background(), device, false)
	require.NoError(t, err)

	var parsed map[string]any
	err = yaml.Unmarshal([]byte(result), &parsed)
	require.NoError(t, err, "Result should be valid YAML")

	assert.NotNil(t, parsed["analysis"], "YAML output should contain analysis")
}

func TestPrepareForExport_RedactsSensitiveFields_JSON(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		HighAvailability: common.HighAvailability{Password: "secret123"},
		Users: []common.User{{
			Name:    "admin",
			APIKeys: []common.APIKey{{Key: "k1", Secret: testSecretValue}},
		}},
		SNMP: common.SNMPConfig{ROCommunity: "private-community"},
		Certificates: []common.Certificate{
			{Description: "cert1", PrivateKey: "test-private-key-rsa"},
		},
		VPN: common.VPN{
			WireGuard: common.WireGuardConfig{
				Clients: []common.WireGuardClient{{Name: "peer1", PSK: "wg-psk-value"}},
			},
		},
		DHCP: []common.DHCPScope{
			{Interface: "lan", AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6KeyInfoStatementSecret: "dhcp-secret-key"}},
		},
	}

	exported := prepareForExport(device, true)

	// Verify struct-level redaction of sensitive fields.
	assert.Equal(t, redactedValue, exported.HighAvailability.Password)
	assert.Equal(t, redactedValue, exported.Users[0].APIKeys[0].Secret)
	assert.Equal(t, redactedValue, exported.SNMP.ROCommunity)
	assert.Equal(t, redactedValue, exported.Certificates[0].PrivateKey)
	assert.Equal(t, redactedValue, exported.VPN.WireGuard.Clients[0].PSK)
	assert.Equal(t, redactedValue, exported.DHCP[0].AdvancedV6.AdvDHCP6KeyInfoStatementSecret)

	// Verify result is valid JSON.
	result, err := json.MarshalIndent(exported, "", "  ")
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(result, &parsed))
}

func TestRedactSensitiveFields_HAPassword(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		HighAvailability: common.HighAvailability{Password: "secret123"},
	}

	result := prepareForExport(device, true)

	assert.Equal(t, redactedValue, result.HighAvailability.Password)
	assert.Equal(t, "secret123", device.HighAvailability.Password, "original not mutated")
}

func TestRedactSensitiveFields_CertificatePrivateKeys(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Certificates: []common.Certificate{
			{Description: "cert1", PrivateKey: "test-private-key-rsa"},
			{Description: "cert2", PrivateKey: ""},
			{Description: "cert3", PrivateKey: "test-private-key-ec"},
		},
	}

	result := prepareForExport(device, true)

	assert.Equal(t, redactedValue, result.Certificates[0].PrivateKey)
	assert.Empty(t, result.Certificates[1].PrivateKey, "empty key should stay empty")
	assert.Equal(t, redactedValue, result.Certificates[2].PrivateKey)
	assert.Equal(t, "test-private-key-rsa", device.Certificates[0].PrivateKey, "original not mutated")
}

func TestRedactSensitiveFields_CAPrivateKeys(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		CAs: []common.CertificateAuthority{
			{Description: "ca1", PrivateKey: "test-private-key-rsa"},
			{Description: "ca2", PrivateKey: ""},
			{Description: "ca3", PrivateKey: "test-private-key-ec"},
		},
	}

	result := prepareForExport(device, true)

	assert.Equal(t, redactedValue, result.CAs[0].PrivateKey)
	assert.Empty(t, result.CAs[1].PrivateKey, "empty key should stay empty")
	assert.Equal(t, redactedValue, result.CAs[2].PrivateKey)
	assert.Equal(t, "test-private-key-rsa", device.CAs[0].PrivateKey, "original not mutated")
}

func TestRedactSensitiveFields_APIKeySecrets(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		Users: []common.User{
			{
				Name: "admin",
				APIKeys: []common.APIKey{
					{Key: "key1", Secret: "secret-a"},
					{Key: "key2", Secret: "secret-b"},
				},
			},
			{Name: "readonly"},
		},
	}

	result := prepareForExport(device, true)

	assert.Equal(t, redactedValue, result.Users[0].APIKeys[0].Secret)
	assert.Equal(t, redactedValue, result.Users[0].APIKeys[1].Secret)
	assert.Empty(t, result.Users[1].APIKeys, "user with no keys unchanged")
	assert.Equal(t, "secret-a", device.Users[0].APIKeys[0].Secret, "original not mutated")
}

func TestRedactSensitiveFields_SNMPCommunity(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		SNMP: common.SNMPConfig{ROCommunity: "public"},
	}

	result := prepareForExport(device, true)

	assert.Equal(t, redactedValue, result.SNMP.ROCommunity)
	assert.Equal(t, "public", device.SNMP.ROCommunity, "original not mutated")
}

func TestRedactSensitiveFields_WireGuardPSK(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		VPN: common.VPN{
			WireGuard: common.WireGuardConfig{
				Clients: []common.WireGuardClient{
					{Name: "peer1", PSK: "presharedkey123"},
					{Name: "peer2", PSK: ""},
				},
			},
		},
	}

	result := prepareForExport(device, true)

	assert.Equal(t, redactedValue, result.VPN.WireGuard.Clients[0].PSK)
	assert.Empty(t, result.VPN.WireGuard.Clients[1].PSK, "empty PSK should stay empty")
	assert.Equal(t, "presharedkey123", device.VPN.WireGuard.Clients[0].PSK, "original not mutated")
}

func TestRedactSensitiveFields_DHCPv6Secret(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		DHCP: []common.DHCPScope{
			{Interface: "lan", AdvancedV6: &common.DHCPAdvancedV6{AdvDHCP6KeyInfoStatementSecret: "dhcp-secret"}},
			{Interface: "opt1"},
		},
	}

	result := prepareForExport(device, true)

	assert.Equal(t, redactedValue, result.DHCP[0].AdvancedV6.AdvDHCP6KeyInfoStatementSecret)
	assert.Nil(t, result.DHCP[1].AdvancedV6, "nil AdvancedV6 should stay nil")
	assert.Equal(t, "dhcp-secret", device.DHCP[0].AdvancedV6.AdvDHCP6KeyInfoStatementSecret, "original not mutated")
}

func TestRedactSensitiveFields_EmptyFieldsNotRedacted(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{}

	result := prepareForExport(device, true)

	assert.Empty(t, result.HighAvailability.Password)
	assert.Empty(t, result.SNMP.ROCommunity)
	assert.Empty(t, result.Certificates)
	assert.Empty(t, result.Users)
	assert.Empty(t, result.VPN.WireGuard.Clients)
	assert.Empty(t, result.DHCP)
}

func TestComputeStatistics_IDSContributesToSecurityScore(t *testing.T) {
	t.Parallel()

	// IDS enabled without IPS.
	deviceIDSOnly := &common.CommonDevice{
		IDS: &common.IDSConfig{Enabled: true},
	}
	statsIDSOnly := analysis.ComputeStatistics(deviceIDSOnly)
	assert.GreaterOrEqual(t, statsIDSOnly.Summary.SecurityScore, 15,
		"IDS enabled should contribute at least 15 points")

	// IDS enabled with IPS mode.
	deviceIDSIPS := &common.CommonDevice{
		IDS: &common.IDSConfig{Enabled: true, IPSMode: true},
	}
	statsIDSIPS := analysis.ComputeStatistics(deviceIDSIPS)
	assert.GreaterOrEqual(t, statsIDSIPS.Summary.SecurityScore, 25,
		"IDS enabled + IPS mode should contribute at least 25 points")

	// IDS disabled — should not contribute.
	deviceIDSOff := &common.CommonDevice{
		IDS: &common.IDSConfig{Enabled: false},
	}
	statsIDSOff := analysis.ComputeStatistics(deviceIDSOff)
	assert.Less(t, statsIDSOff.Summary.SecurityScore, statsIDSOnly.Summary.SecurityScore,
		"IDS disabled should score lower than IDS enabled")
}

func TestComputeStatistics_NATEntriesCountsBothDirections(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		NAT: common.NATConfig{
			OutboundRules: []common.NATRule{{UUID: "o1"}, {UUID: "o2"}},
			InboundRules:  []common.InboundNATRule{{UUID: "i1"}},
		},
	}

	stats := analysis.ComputeStatistics(device)
	assert.Equal(t, 3, stats.NATEntries, "NATEntries should count both outbound and inbound rules")
}

func TestPrepareForExport_NoRedact_PreservesSensitiveFields(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		HighAvailability: common.HighAvailability{Password: "secret123"},
		SNMP:             common.SNMPConfig{ROCommunity: "private-community"},
		Certificates: []common.Certificate{
			{Description: "cert1", PrivateKey: "test-private-key-rsa"},
		},
		VPN: common.VPN{
			WireGuard: common.WireGuardConfig{
				Clients: []common.WireGuardClient{{Name: "peer1", PSK: "wg-psk-value"}},
			},
		},
	}

	result := prepareForExport(device, false)

	assert.Equal(t, "secret123", result.HighAvailability.Password, "HA password should be preserved")
	assert.Equal(t, "private-community", result.SNMP.ROCommunity, "SNMP community should be preserved")
	assert.Equal(
		t,
		"test-private-key-rsa",
		result.Certificates[0].PrivateKey,
		"cert key should be preserved",
	)
	assert.Equal(t, "wg-psk-value", result.VPN.WireGuard.Clients[0].PSK, "WireGuard PSK should be preserved")
	assert.NotContains(t, result.HighAvailability.Password, "[REDACTED]")
}

func TestComputeStatistics_SNMPCommunityInServiceDetails(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		SNMP: common.SNMPConfig{
			ROCommunity: "my-community",
			SysLocation: testSNMPLocation,
			SysContact:  "admin@example.com",
		},
	}

	stats := analysis.ComputeStatistics(device)

	require.NotEmpty(t, stats.ServiceDetails, "ServiceDetails should contain SNMP entry")

	var snmpService *common.ServiceStatistics
	for i := range stats.ServiceDetails {
		if stats.ServiceDetails[i].Name == analysis.ServiceNameSNMP {
			snmpService = &stats.ServiceDetails[i]

			break
		}
	}

	require.NotNil(t, snmpService, "SNMP Daemon should be in ServiceDetails")
	assert.Equal(t, "my-community", snmpService.Details["community"],
		"ServiceDetails should contain the actual SNMP community, not [REDACTED]")
	assert.Equal(t, testSNMPLocation, snmpService.Details["location"])
	assert.Equal(t, "admin@example.com", snmpService.Details["contact"])
}

func TestPrepareForExport_Redact_SNMPCommunityInServiceDetails(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		SNMP: common.SNMPConfig{
			ROCommunity: "secret-community",
			SysLocation: "datacenter",
			SysContact:  "ops@example.com",
		},
	}

	result := prepareForExport(device, true)

	// The top-level SNMP field should be redacted.
	assert.Equal(t, redactedValue, result.SNMP.ROCommunity)

	// Statistics.ServiceDetails should also have the community redacted.
	require.NotNil(t, result.Statistics, "Statistics should be populated")

	var snmpService *common.ServiceStatistics
	for i := range result.Statistics.ServiceDetails {
		if result.Statistics.ServiceDetails[i].Name == analysis.ServiceNameSNMP {
			snmpService = &result.Statistics.ServiceDetails[i]

			break
		}
	}

	require.NotNil(t, snmpService, "SNMP Daemon should be in ServiceDetails")
	assert.Equal(t, redactedValue, snmpService.Details["community"],
		"ServiceDetails community should be redacted")
	assert.Equal(t, "datacenter", snmpService.Details["location"],
		"Non-sensitive details should be preserved")
	assert.Equal(t, "ops@example.com", snmpService.Details["contact"],
		"Non-sensitive details should be preserved")

	// Original device must not be mutated.
	assert.Equal(t, "secret-community", device.SNMP.ROCommunity, "original not mutated")
}

func TestNewFieldsSerialization(t *testing.T) {
	RunNewFieldsSerializationTests(t)
}

func TestEnrichForExport_PopulatesNilFields(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{Hostname: "h", Domain: "d"},
	}

	EnrichForExport(device)

	assert.Equal(t, common.DeviceTypeOPNsense, device.DeviceType)
	require.NotNil(t, device.Statistics)
	require.NotNil(t, device.Analysis)
	require.NotNil(t, device.SecurityAssessment)
	require.NotNil(t, device.PerformanceMetrics)
}

func TestEnrichForExport_PreservesExistingFields(t *testing.T) {
	t.Parallel()

	stats := &common.Statistics{TotalInterfaces: 7}
	analysisIn := &common.Analysis{}
	secAssess := &common.SecurityAssessment{}
	perfMetrics := &common.PerformanceMetrics{}
	device := &common.CommonDevice{
		DeviceType:         common.DeviceTypePfSense,
		Statistics:         stats,
		Analysis:           analysisIn,
		SecurityAssessment: secAssess,
		PerformanceMetrics: perfMetrics,
	}

	EnrichForExport(device)

	assert.Equal(t, common.DeviceTypePfSense, device.DeviceType, "existing DeviceType preserved")
	assert.Same(t, stats, device.Statistics, "existing Statistics pointer preserved")
	assert.Same(t, analysisIn, device.Analysis, "existing Analysis pointer preserved")
	assert.Same(t, secAssess, device.SecurityAssessment, "existing SecurityAssessment pointer preserved")
	assert.Same(t, perfMetrics, device.PerformanceMetrics, "existing PerformanceMetrics pointer preserved")
}

func TestEnrichForExport_NilDeviceIsSafe(t *testing.T) {
	t.Parallel()

	assert.NotPanics(t, func() {
		EnrichForExport(nil)
	})
}

func TestEnrichForExport_FanOutFromSingleEnrichedDeviceIsRaceClean(t *testing.T) {
	// EnrichForExport's documented supported pattern is "one device, enrich
	// once, fan out exports": a caller invokes EnrichForExport on a *CommonDevice,
	// then dispatches concurrent prepareForExport calls that each consume the
	// cached Statistics/Analysis pointers. This test pins that pattern under
	// `go test -race`. If a future refactor starts mutating the cached
	// Statistics from prepareForExport (e.g., the redact-path drops its
	// clone-on-write), the race detector flags the concurrent reads against
	// the fan-out write.
	t.Parallel()

	device := &common.CommonDevice{
		SNMP: common.SNMPConfig{
			ROCommunity: testSecretValue,
			SysLocation: testSNMPLocation,
		},
	}
	EnrichForExport(device)

	const goroutines = 8
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		redact := i%2 == 0
		go func() {
			defer wg.Done()
			out := prepareForExport(device, redact)
			if out.Statistics == nil {
				t.Errorf("Statistics nil after concurrent prepareForExport (redact=%v)", redact)
				return
			}
			details := out.Statistics.ServiceDetails
			for j := range details {
				if details[j].Name != analysis.ServiceNameSNMP || details[j].Details == nil {
					continue
				}
				got := details[j].Details["community"]
				want := testSecretValue
				if redact {
					want = redactedValue
				}
				if got != want {
					t.Errorf("redact=%v: SNMP community = %q, want %q", redact, got, want)
				}
			}
		}()
	}
	wg.Wait()
}

func TestEnrichForExport_PrepareForExportSkipsRecomputation(t *testing.T) {
	// Memoization invariant: after EnrichForExport, every prepareForExport call
	// must reuse the cached Statistics/Analysis pointers (the heavy work runs
	// once). This is the core memoization contract — multi-format exports do
	// not recompute analysis per format.
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{Hostname: "h"},
	}

	EnrichForExport(device)

	cachedStats := device.Statistics
	cachedAnalysis := device.Analysis

	for _, redact := range []bool{false, true} {
		out := prepareForExport(device, redact)
		// Source-of-truth invariant: the cache on the input device is never
		// mutated by prepareForExport, regardless of redact direction.
		assert.Same(t, cachedStats, device.Statistics,
			"EnrichForExport result must outlive prepareForExport (redact=%v)", redact)
		assert.Same(t, cachedAnalysis, device.Analysis,
			"EnrichForExport result must outlive prepareForExport (redact=%v)", redact)
		// Returned device reuses the cached Analysis pointer (Analysis is
		// never cloned by the redact path).
		assert.Same(t, cachedAnalysis, out.Analysis,
			"returned device reuses cached Analysis (redact=%v)", redact)
	}

	// Returned-Statistics pointer identity on the non-redact path is the
	// memoization invariant. The redact path's pointer identity depends on
	// whether the fixture has SNMP redaction to do, so it is pinned separately
	// by TestRedactStatisticsServiceDetails_NoSNMPCommunity_ReturnsInputUnchanged.
	plain := prepareForExport(device, false)
	assert.Same(t, cachedStats, plain.Statistics,
		"non-redact path returns cached Statistics directly")
}

func TestEnrichForExport_RedactDoesNotLeakIntoCachedStatistics(t *testing.T) {
	// Safety invariant: prepareForExport(redact=true) must not mutate the
	// Statistics that EnrichForExport produced. Otherwise a subsequent
	// non-redacted export would observe redacted values, and a caller that
	// inspects device.Statistics after a redacted export would see leaked
	// redaction markers.
	t.Parallel()

	device := &common.CommonDevice{
		SNMP: common.SNMPConfig{
			ROCommunity: testSecretValue,
			SysLocation: testSNMPLocation,
		},
	}

	EnrichForExport(device)

	snmpDetailsBefore := snmpDetails(t, device.Statistics)
	require.Equal(t, testSecretValue, snmpDetailsBefore["community"],
		"baseline: enriched Statistics carries the unredacted community")

	redacted := prepareForExport(device, true)

	// Redacted export sees redacted community.
	require.Equal(t, redactedValue, snmpDetails(t, redacted.Statistics)["community"])

	// Cached Statistics on the original device retains the unredacted community.
	assert.Equal(t, testSecretValue, snmpDetails(t, device.Statistics)["community"],
		"cached Statistics must not be mutated by prepareForExport(redact=true)")

	// And a subsequent non-redacted export still sees the real community.
	plain := prepareForExport(device, false)
	assert.Equal(t, testSecretValue, snmpDetails(t, plain.Statistics)["community"],
		"non-redacted export after a redacted export still observes real values")
}

func TestEnrichForExport_NonRedactThenRedactDoesNotLeakIntoCachedStatistics(t *testing.T) {
	// Reverse-direction safety invariant for the redaction-leak contract: a
	// caller that does a non-redacted export first, then a redacted export on
	// the same enriched device, must see the redacted output carry [REDACTED]
	// while the cached Statistics on the original device retains the
	// unredacted community.
	t.Parallel()

	device := &common.CommonDevice{
		SNMP: common.SNMPConfig{
			ROCommunity: testSecretValue,
			SysLocation: testSNMPLocation,
		},
	}

	EnrichForExport(device)

	plain := prepareForExport(device, false)
	require.Equal(t, testSecretValue, snmpDetails(t, plain.Statistics)["community"],
		"baseline: non-redact export observes the real community")

	redacted := prepareForExport(device, true)
	assert.Equal(t, redactedValue, snmpDetails(t, redacted.Statistics)["community"],
		"redact export after a non-redact export still produces redacted output")
	assert.Equal(t, testSecretValue, snmpDetails(t, device.Statistics)["community"],
		"cached Statistics must not be mutated by the redact export that followed")
}

func TestRedactStatisticsServiceDetails_NoSNMPCommunity_ReturnsInputUnchanged(t *testing.T) {
	// Pins the early-return-same-pointer path in redactStatisticsServiceDetails:
	// when no SNMP entry has a "community" key, the function must return the
	// input pointer verbatim (no struct/slice clone).
	t.Parallel()

	tests := []struct {
		name    string
		details map[string]string
	}{
		{name: "nil details", details: nil},
		{name: "missing community key", details: map[string]string{"location": testSNMPLocation}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stats := &common.Statistics{
				ServiceDetails: []common.ServiceStatistics{
					{Name: analysis.ServiceNameSNMP, Details: tc.details},
				},
			}
			out := redactStatisticsServiceDetails(stats)
			assert.Same(t, stats, out, "no-redaction path must return input pointer unchanged")
		})
	}
}

func TestRedactStatisticsServiceDetails_MultipleSNMPEntries_AllRedacted(t *testing.T) {
	// Defense-in-depth: if a future analysis writer ever emits multiple SNMP
	// service entries (SNMPv3, separate read/write communities, multi-instance
	// agents), every one of them carries cleartext community on the unredacted
	// path. The redactor must redact ALL matches, not just the first.
	t.Parallel()

	stats := &common.Statistics{
		ServiceDetails: []common.ServiceStatistics{
			{Name: analysis.ServiceNameSNMP, Details: map[string]string{"community": "first"}},
			{Name: "Other Service", Details: map[string]string{"foo": "bar"}},
			{Name: analysis.ServiceNameSNMP, Details: map[string]string{"community": "second"}},
		},
	}

	out := redactStatisticsServiceDetails(stats)
	require.NotNil(t, out)
	assert.Equal(t, redactedValue, out.ServiceDetails[0].Details["community"], "first SNMP entry redacted")
	assert.Equal(t, redactedValue, out.ServiceDetails[2].Details["community"], "second SNMP entry redacted")
	// Input is not mutated.
	assert.Equal(t, "first", stats.ServiceDetails[0].Details["community"], "input first SNMP entry unchanged")
	assert.Equal(t, "second", stats.ServiceDetails[2].Details["community"], "input second SNMP entry unchanged")
}

func snmpDetails(t *testing.T, stats *common.Statistics) map[string]string {
	t.Helper()
	require.NotNil(t, stats)
	for i := range stats.ServiceDetails {
		if stats.ServiceDetails[i].Name == analysis.ServiceNameSNMP {
			return stats.ServiceDetails[i].Details
		}
	}
	t.Fatalf("SNMP service entry not found in ServiceDetails")
	return nil
}
