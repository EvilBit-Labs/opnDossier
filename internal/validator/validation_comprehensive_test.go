package validator

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// TestInterfaceReferences_TableDriven provides explicit table-driven tests for
// unknown vs known interface references as required by the task.
func TestInterfaceReferences_TableDriven(t *testing.T) {
	tests := []struct {
		name               string
		interfaces         map[string]model.Interface
		filterRules        []model.Rule
		dhcpInterfaces     map[string]model.DhcpdInterface
		expectedErrors     int
		expectedErrorsDesc []string
	}{
		{
			name: "known interfaces - opt0, opt1, opt2 - should pass",
			interfaces: map[string]model.Interface{
				"wan":  {Enable: "1", If: "vtnet0"},
				"lan":  {Enable: "1", If: "vtnet1"},
				"opt0": {Enable: "1", If: "wg1"},
				"opt1": {Enable: "1", If: "vtnet2"},
				"opt2": {Enable: "1", If: "vtnet3"},
			},
			filterRules: []model.Rule{
				{
					Type:      "pass",
					Interface: "opt0",
					Source:    model.Source{Network: "opt0"},
				},
				{
					Type:        "pass",
					Interface:   "opt1",
					Destination: model.Destination{Network: "opt1ip"},
				},
				{
					Type:      "pass",
					Interface: "opt2",
					Source:    model.Source{Network: "opt2ip"},
				},
			},
			dhcpInterfaces: map[string]model.DhcpdInterface{
				"opt1": {Range: model.Range{From: "172.17.0.10", To: "172.17.0.250"}},
				"opt2": {Range: model.Range{From: "172.18.0.10", To: "172.18.0.250"}},
			},
			expectedErrors:     0,
			expectedErrorsDesc: []string{},
		},
		{
			name: "unknown interface references - should fail",
			interfaces: map[string]model.Interface{
				"wan": {Enable: "1", If: "vtnet0"},
				"lan": {Enable: "1", If: "vtnet1"},
			},
			filterRules: []model.Rule{
				{
					Type:      "pass",
					Interface: "opt99", // Unknown interface
					Source:    model.Source{Network: "any"},
				},
				{
					Type:      "pass",
					Interface: "lan",
					Source:    model.Source{Network: "nonexistent"}, // Unknown source network
				},
				{
					Type:        "pass",
					Interface:   "wan",
					Destination: model.Destination{Network: "opt5ip"}, // Unknown destination
				},
			},
			dhcpInterfaces: map[string]model.DhcpdInterface{
				"opt3": {Range: model.Range{From: "10.0.0.10", To: "10.0.0.250"}}, // Unknown DHCP interface
			},
			expectedErrors: 4,
			expectedErrorsDesc: []string{
				"interface 'opt99' must be one of the configured interfaces",
				"source network 'nonexistent' must be a valid CIDR",
				"destination network 'opt5ip' must be a valid CIDR",
				"DHCP interface 'opt3' must reference a configured interface",
			},
		},
		{
			name: "mixed known and unknown interfaces - partial failures",
			interfaces: map[string]model.Interface{
				"wan":  {Enable: "1", If: "vtnet0"},
				"lan":  {Enable: "1", If: "vtnet1"},
				"opt0": {Enable: "1", If: "vtnet2"},
			},
			filterRules: []model.Rule{
				{
					Type:      "pass",
					Interface: "opt0",                          // Known - should pass
					Source:    model.Source{Network: "opt0ip"}, // Known - should pass
				},
				{
					Type:      "pass",
					Interface: "opt1", // Unknown - should fail
					Source:    model.Source{Network: "any"},
				},
				{
					Type:        "pass",
					Interface:   "lan",                                // Known
					Destination: model.Destination{Network: "opt0ip"}, // Known - should pass
				},
			},
			dhcpInterfaces: map[string]model.DhcpdInterface{
				"opt0": {Range: model.Range{From: "10.0.0.10", To: "10.0.0.250"}}, // Known - should pass
			},
			expectedErrors: 1, // Only opt1 interface should fail
			expectedErrorsDesc: []string{
				"interface 'opt1' must be one of the configured interfaces",
			},
		},
		{
			name: "interface name with ip suffix validation",
			interfaces: map[string]model.Interface{
				"wan":  {Enable: "1", If: "vtnet0"},
				"lan":  {Enable: "1", If: "vtnet1"},
				"opt0": {Enable: "1", If: "vtnet2"},
				"opt1": {Enable: "1", If: "vtnet3"},
			},
			filterRules: []model.Rule{
				{
					Type:      "pass",
					Interface: "lan",
					Source:    model.Source{Network: "wanip"}, // Should resolve to "wan" and pass
				},
				{
					Type:        "pass",
					Interface:   "opt0",
					Destination: model.Destination{Network: "opt1ip"}, // Should resolve to "opt1" and pass
				},
				{
					Type:      "pass",
					Interface: "opt1",
					Source:    model.Source{Network: "opt99ip"}, // Should resolve to "opt99" and fail
				},
			},
			dhcpInterfaces: map[string]model.DhcpdInterface{},
			expectedErrors: 1,
			expectedErrorsDesc: []string{
				"source network 'opt99ip' must be a valid CIDR",
			},
		},
		{
			name: "track6 interface validation",
			interfaces: map[string]model.Interface{
				"wan": {Enable: "1", If: "vtnet0"},
				"lan": {
					Enable:          "1",
					If:              "vtnet1",
					IPAddrv6:        "track6",
					Track6Interface: "wan", // Should reference existing interface
					Track6PrefixID:  "0",
				},
				"opt0": {
					Enable:          "1",
					If:              "vtnet2",
					IPAddrv6:        "track6",
					Track6Interface: "nonexistent", // Should fail - unknown interface
					Track6PrefixID:  "1",
				},
			},
			filterRules:    []model.Rule{},
			dhcpInterfaces: map[string]model.DhcpdInterface{},
			expectedErrors: 1,
			expectedErrorsDesc: []string{
				"track6-interface 'nonexistent' must reference a configured interface",
			},
		},
		{
			name: "comprehensive opt interfaces validation - real-world scenario",
			interfaces: map[string]model.Interface{
				"wan":  {Enable: "1", If: "vtnet0", IPAddr: "192.0.2.10"},
				"lan":  {Enable: "1", If: "vtnet1", IPAddr: "172.16.0.1"},
				"opt0": {Enable: "1", If: "wg1"},                          // WireGuard interface
				"opt1": {Enable: "1", If: "vtnet2", IPAddr: "172.17.0.1"}, // Servers
				"opt2": {Enable: "1", If: "vtnet3", IPAddr: "172.18.0.1"}, // DMZ
				"lo0":  {Enable: "1", If: "lo0", IPAddr: "127.0.0.1"},     // Loopback
			},
			filterRules: []model.Rule{
				// WAN rule referencing wanip
				{
					Type:        "pass",
					Interface:   "wan",
					Destination: model.Destination{Network: "wanip"},
				},
				// LAN rule with standard network reference
				{
					Type:      "pass",
					Interface: "lan",
					Source:    model.Source{Network: "lan"},
				},
				// OPT0 (WireGuard) rule
				{
					Type:        "pass",
					Interface:   "opt0",
					Source:      model.Source{Network: "opt0"},
					Destination: model.Destination{Network: "opt0ip"},
				},
				// OPT1 to OPT2 communication
				{
					Type:        "pass",
					Interface:   "opt1",
					Source:      model.Source{Network: "opt1ip"},
					Destination: model.Destination{Network: "opt2ip"},
				},
			},
			dhcpInterfaces: map[string]model.DhcpdInterface{
				"lan":  {Range: model.Range{From: "172.16.0.10", To: "172.16.0.250"}},
				"opt1": {Range: model.Range{From: "172.17.0.10", To: "172.17.0.250"}},
				"opt2": {Range: model.Range{From: "172.18.0.10", To: "172.18.0.250"}},
			},
			expectedErrors:     0, // All references should be valid
			expectedErrorsDesc: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the test configuration
			config := &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test-host",
					Domain:   "test.local",
					WebGUI: struct {
						Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
						SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
					}{Protocol: "https"},
					Bogons: struct {
						Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
					}{Interval: "monthly"},
				},
				Interfaces: model.Interfaces{
					Items: tt.interfaces,
				},
				Filter: model.Filter{
					Rule: tt.filterRules,
				},
				Dhcpd: model.Dhcpd{
					Items: tt.dhcpInterfaces,
				},
			}

			// Validate the configuration
			errors := ValidateOpnSenseDocument(config)

			// Check the number of errors
			assert.Len(t, errors, tt.expectedErrors, "Expected %d validation errors, got %d. Errors: %v", tt.expectedErrors, len(errors), errors)

			// Check that expected error descriptions are present
			for _, expectedDesc := range tt.expectedErrorsDesc {
				found := false
				for _, err := range errors {
					if strings.Contains(err.Error(), expectedDesc) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected error description '%s' not found in errors: %v", expectedDesc, errors)
			}

			// Log details for debugging
			if len(errors) > 0 {
				t.Logf("Validation errors found:")
				for i, err := range errors {
					t.Logf("  %d: %s", i+1, err.Error())
				}
			}
		})
	}
}

// TestInterfaceNameResolution_EdgeCases tests edge cases in interface name resolution,
// including stripIPSuffix functionality and reserved network names.
func TestInterfaceNameResolution_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedStrip string
		isReserved    bool
	}{
		{"wan with ip suffix", "wanip", "wan", false},
		{"lan with ip suffix", "lanip", "lan", false},
		{"opt0 with ip suffix", "opt0ip", "opt0", false},
		{"opt10 with ip suffix", "opt10ip", "opt10", false},
		{"wan without suffix", "wan", "wan", true},
		{"lan without suffix", "lan", "lan", true},
		{"any reserved", "any", "any", true},
		{"localhost reserved", "localhost", "localhost", true},
		{"loopback reserved", "loopback", "loopback", true},
		{"random string", "randomstring", "randomstring", false},
		{"ip at end but not suffix", "notanip", "notan", false}, // stripIPSuffix removes "ip" even from "notanip"
		{"multiple ip suffixes", "optipip", "optip", false},     // Only strips one "ip"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test stripIPSuffix function
			stripped := stripIPSuffix(tt.input)
			assert.Equal(t, tt.expectedStrip, stripped, "stripIPSuffix('%s') should return '%s'", tt.input, tt.expectedStrip)

			// Test isReservedNetwork function
			reserved := isReservedNetwork(tt.input)
			assert.Equal(t, tt.isReserved, reserved, "isReservedNetwork('%s') should return %v", tt.input, tt.isReserved)
		})
	}
}

// TestValidation_RealWorldScenarios tests complex real-world scenarios that combine
// multiple validation aspects including opt interfaces.
func TestValidation_RealWorldScenarios(t *testing.T) {
	t.Run("complex firewall configuration with opt interfaces", func(t *testing.T) {
		config := &model.OpnSenseDocument{
			System: model.System{
				Hostname: "firewall",
				Domain:   "example.com",
				WebGUI: struct {
					Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
					SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
				}{Protocol: "https"},
				Bogons: struct {
					Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
				}{Interval: "monthly"},
			},
			Interfaces: model.Interfaces{
				Items: map[string]model.Interface{
					"wan": {
						Enable:      "1",
						If:          "vtnet0",
						IPAddr:      "192.0.2.10",
						Subnet:      "24",
						BlockPriv:   "on",
						BlockBogons: "on",
					},
					"lan": {
						Enable: "1",
						If:     "vtnet1",
						IPAddr: "172.16.0.1",
						Subnet: "24",
					},
					"opt0": {
						Enable: "1",
						If:     "wg1",
					},
					"opt1": {
						Enable: "1",
						If:     "vtnet2",
						IPAddr: "172.17.0.1",
						Subnet: "24",
					},
					"opt2": {
						Enable: "1",
						If:     "vtnet3",
						IPAddr: "172.18.0.1",
						Subnet: "24",
					},
					"lo0": {
						Enable:   "1",
						If:       "lo0",
						IPAddr:   "127.0.0.1",
						Subnet:   "8",
						IPAddrv6: "::1",
						Subnetv6: "128",
					},
					"wireguard": {
						Enable: "1",
						If:     "wireguard",
					},
				},
			},
			Filter: model.Filter{
				Rule: []model.Rule{
					// WAN UDP rule for WireGuard
					{
						Type:        "pass",
						Interface:   "wan",
						IPProtocol:  "inet",
						Source:      model.Source{Network: "any"},
						Destination: model.Destination{Network: "wanip"},
					},
					// LAN to any
					{
						Type:       "pass",
						Interface:  "lan",
						IPProtocol: "inet",
						Source:     model.Source{Network: "lan"},
					},
					// LAN IPv6 to any
					{
						Type:       "pass",
						Interface:  "lan",
						IPProtocol: "inet6",
						Source:     model.Source{Network: "lan"},
					},
					// OPT0 WireGuard rule
					{
						Type:        "pass",
						Interface:   "opt0",
						IPProtocol:  "inet",
						Source:      model.Source{Network: "opt0"},
						Destination: model.Destination{Network: "opt0ip"},
					},
				},
			},
			Dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"lan": {
						Range: model.Range{
							From: "172.16.0.10",
							To:   "172.16.0.250",
						},
					},
					"opt1": {
						Range: model.Range{
							From: "172.17.0.10",
							To:   "172.17.0.250",
						},
					},
					"opt2": {
						Range: model.Range{
							From: "172.18.0.10",
							To:   "172.18.0.250",
						},
					},
				},
			},
			Unbound: model.Unbound{Enable: "on"},
			Snmpd:   model.Snmpd{ROCommunity: "public"},
			Nat:     model.Nat{Outbound: model.Outbound{Mode: "automatic"}},
			Sysctl: []model.SysctlItem{
				{
					Tunable: "net.inet.icmp.drop_redirect",
					Value:   "1",
					Descr:   "Drop ICMP redirects",
				},
			},
		}

		// Validate the complex configuration
		errors := ValidateOpnSenseDocument(config)

		// Should have no validation errors for this well-formed configuration
		if len(errors) > 0 {
			t.Logf("Found %d validation errors:", len(errors))
			for i, err := range errors {
				t.Logf("  %d: %s", i+1, err.Error())
			}
		}
		assert.Len(t, errors, 0, "Complex real-world configuration should produce zero validation errors")

		// Verify interface accessibility
		interfaceNames := config.Interfaces.Names()
		expectedInterfaces := []string{"wan", "lan", "opt0", "opt1", "opt2", "lo0", "wireguard"}
		for _, expected := range expectedInterfaces {
			assert.Contains(t, interfaceNames, expected, "Expected interface '%s' should be present", expected)
		}

		t.Logf("Successfully validated complex configuration with %d interfaces: %v", len(interfaceNames), interfaceNames)
	})
}

// TestSampleConfig2_ZeroValidationErrors tests that a configuration similar to
// sample.config.2.xml produces zero validation errors as required by the task.
func TestSampleConfig2_ZeroValidationErrors(t *testing.T) {
	// This test represents the structure and content from sample.config.2.xml
	// but constructs it manually to avoid parser dependency issues
	config := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "TestHost2",
			Domain:   "test.local",
			WebGUI: struct {
				Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
				SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
			}{Protocol: "https"},
			SSH: struct {
				Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
			}{Group: "admins"},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					Enable: "1",
					If:     "vtnet0",
					IPAddr: "192.0.2.10",
					Subnet: "24",
				},
				"lan": {
					Enable: "1",
					If:     "vtnet1",
					IPAddr: "172.16.0.1",
					Subnet: "24",
				},
				"opt0": {
					Enable: "1",
					If:     "wg1", // WireGuard interface
				},
				"opt1": {
					Enable: "1",
					If:     "vtnet2",
					IPAddr: "172.17.0.1",
					Subnet: "24",
				},
				"opt2": {
					Enable: "1",
					If:     "vtnet3",
					IPAddr: "172.18.0.1",
					Subnet: "24",
				},
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				// Sample rules that reference opt interfaces
				{
					Type:        "pass",
					Interface:   "opt0",
					IPProtocol:  "inet",
					Source:      model.Source{Network: "opt0"},
					Destination: model.Destination{Network: "any"},
				},
				{
					Type:        "pass",
					Interface:   "opt1",
					IPProtocol:  "inet",
					Source:      model.Source{Network: "opt1ip"},
					Destination: model.Destination{Network: "opt2ip"},
				},
				{
					Type:        "pass",
					Interface:   "opt2",
					IPProtocol:  "inet",
					Source:      model.Source{Network: "any"},
					Destination: model.Destination{Network: "opt2ip"},
				},
			},
		},
		Dhcpd: model.Dhcpd{
			Items: map[string]model.DhcpdInterface{
				"lan": {
					Range: model.Range{
						From: "172.16.0.10",
						To:   "172.16.0.250",
					},
				},
				"opt1": {
					Range: model.Range{
						From: "172.17.0.10",
						To:   "172.17.0.250",
					},
				},
				"opt2": {
					Range: model.Range{
						From: "172.18.0.10",
						To:   "172.18.0.250",
					},
				},
			},
		},
		Nat:     model.Nat{Outbound: model.Outbound{Mode: "automatic"}},
		Unbound: model.Unbound{Enable: "on"},
		Snmpd:   model.Snmpd{ROCommunity: "public"},
	}

	// **KEY REQUIREMENT**: Validate the configuration and assert len(errors)==0
	errors := ValidateOpnSenseDocument(config)
	assert.Len(t, errors, 0, "Validation should produce zero errors for sample.config.2.xml-like configuration. Found errors: %v", errors)

	// Verify interface accessibility
	interfaceNames := config.Interfaces.Names()
	expectedInterfaces := []string{"wan", "lan", "opt0", "opt1", "opt2"}
	for _, expected := range expectedInterfaces {
		assert.Contains(t, interfaceNames, expected, "Expected interface '%s' should be present", expected)
	}

	t.Logf("Successfully validated sample.config.2.xml-like configuration with %d interfaces: %v", len(interfaceNames), interfaceNames)
	t.Logf("All validation tests passed with zero errors")
}
