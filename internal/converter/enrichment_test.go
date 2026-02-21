package converter

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestPrepareForExport_PopulatesStatistics(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
	}

	result := prepareForExport(device)

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

	result := prepareForExport(device)

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

	result := prepareForExport(device)

	assert.Same(t, existing, result.Statistics, "Existing Statistics should be preserved")
	assert.Equal(t, 42, result.Statistics.TotalInterfaces)
}

func TestPrepareForExport_PreservesExistingAnalysis(t *testing.T) {
	t.Parallel()

	existing := &common.Analysis{
		SecurityIssues: []common.SecurityFinding{{Issue: "pre-existing"}},
	}
	device := &common.CommonDevice{
		Analysis: existing,
	}

	result := prepareForExport(device)

	assert.Same(t, existing, result.Analysis, "Existing Analysis should be preserved")
}

func TestPrepareForExport_DoesNotMutateInput(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{Hostname: "original"},
	}

	result := prepareForExport(device)

	assert.Equal(t, common.DeviceTypeUnknown, device.DeviceType, "Original should not be mutated")
	assert.Nil(t, device.Statistics, "Original should not be mutated")
	assert.Nil(t, device.Analysis, "Original should not be mutated")
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
	result, err := c.ToJSON(context.Background(), device)
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
	result, err := c.ToYAML(context.Background(), device)
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

	stats := computeStatistics(device)

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

	stats := computeStatistics(device)

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
	analysis := computeAnalysis(device)

	require.NotNil(t, analysis)
	assert.Empty(t, analysis.DeadRules)
	assert.Empty(t, analysis.UnusedInterfaces)
	assert.Empty(t, analysis.SecurityIssues)
	assert.Empty(t, analysis.PerformanceIssues)
	assert.Empty(t, analysis.ConsistencyIssues)
}

func TestComputeAnalysis_DeadRules(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{
				Type:        "block",
				Interfaces:  []string{"wan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
			{
				Type:        "pass",
				Interfaces:  []string{"wan"},
				Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
		},
	}

	analysis := computeAnalysis(device)

	require.NotEmpty(t, analysis.DeadRules)
	assert.Equal(t, "wan", analysis.DeadRules[0].Interface)
	assert.Contains(t, analysis.DeadRules[0].Description, "unreachable")
}

func TestComputeAnalysis_DuplicateRules(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{
				Type:        "pass",
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
			{
				Type:        "pass",
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
		},
	}

	analysis := computeAnalysis(device)

	require.NotEmpty(t, analysis.DeadRules)
	assert.Contains(t, analysis.DeadRules[0].Description, "duplicate")
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

	analysis := computeAnalysis(device)

	require.Len(t, analysis.UnusedInterfaces, 1)
	assert.Equal(t, "opt1", analysis.UnusedInterfaces[0].InterfaceName)
}

func TestComputeAnalysis_SecurityIssues(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System: common.System{
			WebGUI: common.WebGUI{Protocol: "http"},
		},
		SNMP: common.SNMPConfig{ROCommunity: "public"},
		FirewallRules: []common.FirewallRule{
			{Type: "pass", Interfaces: []string{"wan"}, Source: common.RuleEndpoint{Address: "any"}},
		},
	}

	analysis := computeAnalysis(device)

	require.Len(t, analysis.SecurityIssues, 3)

	issues := make(map[string]bool)
	for _, si := range analysis.SecurityIssues {
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

	analysis := computeAnalysis(device)

	require.Len(t, analysis.PerformanceIssues, 2)

	issues := make(map[string]bool)
	for _, pi := range analysis.PerformanceIssues {
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

	analysis := computeAnalysis(device)

	require.NotEmpty(t, analysis.ConsistencyIssues)

	issues := make(map[string]bool)
	for _, ci := range analysis.ConsistencyIssues {
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
	result, err := c.ToJSON(context.Background(), device)
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
	result, err := c.ToYAML(context.Background(), device)
	require.NoError(t, err)

	var parsed map[string]any
	err = yaml.Unmarshal([]byte(result), &parsed)
	require.NoError(t, err, "Result should be valid YAML")

	assert.NotNil(t, parsed["analysis"], "YAML output should contain analysis")
}
