package validator

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestValidateOpnSenseDocument_ValidConfig(t *testing.T) {
	config := &model.OpnSenseDocument{
		System: model.System{
			Hostname:          "test-host",
			Domain:            "test.local",
			Timezone:          "Etc/UTC",
			Optimization:      "normal",
			WebGUI:            model.WebGUIConfig{Protocol: "https"},
			PowerdACMode:      "hadp",
			PowerdBatteryMode: "hadp",
			PowerdNormalMode:  "hadp",
			Bogons: struct {
				Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
			}{Interval: "monthly"},
			Group: []model.Group{
				{
					Name:  "admins",
					Gid:   "1999",
					Scope: "system",
				},
			},
			User: []model.User{
				{
					Name:      "root",
					UID:       "0",
					Groupname: "admins",
					Scope:     "system",
				},
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					IPAddr:   "dhcp",
					IPAddrv6: "dhcp6",
				},
				"lan": {
					IPAddr:          "192.168.1.1",
					Subnet:          "24",
					IPAddrv6:        "track6",
					Subnetv6:        "64",
					Track6Interface: "wan",
					Track6PrefixID:  "0",
				},
				"opt0": {
					IPAddr: "10.0.0.1",
					Subnet: "24",
				},
			},
		},
		Dhcpd: model.Dhcpd{
			Items: map[string]model.DhcpdInterface{
				"lan": {
					Range: model.Range{
						From: "192.168.1.100",
						To:   "192.168.1.199",
					},
				},
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{
					Type:       "pass",
					IPProtocol: "inet",
					Interface:  model.InterfaceList{"lan"},
					Source: model.Source{
						Network: "lan",
					},
					Destination: model.Destination{
						Network: "opt0ip",
					},
				},
			},
		},
		Nat: model.Nat{
			Outbound: model.Outbound{
				Mode: "automatic",
			},
		},
		Sysctl: []model.SysctlItem{
			{
				Tunable: "net.inet.ip.random_id",
				Value:   "default",
				Descr:   "Randomize the ID field in IP packets",
			},
		},
	}

	errors := ValidateOpnSenseDocument(config)
	assert.Empty(t, errors, "Valid configuration should not produce validation errors")
}

func TestStripIPSuffix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with ip suffix",
			input:    "opt0ip",
			expected: "opt0",
		},
		{
			name:     "without ip suffix",
			input:    "opt0",
			expected: "opt0",
		},
		{
			name:     "reserved word",
			input:    "any",
			expected: "any",
		},
		{
			name:     "lanip",
			input:    "lanip",
			expected: "lan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripIPSuffix(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateFilter_NetworkValidation(t *testing.T) {
	interfaces := &model.Interfaces{
		Items: map[string]model.Interface{
			"wan":  {},
			"lan":  {},
			"opt0": {},
		},
	}

	tests := []struct {
		name           string
		filter         model.Filter
		expectedErrors int
		errorField     string
	}{
		{
			name: "valid reserved network",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface: model.InterfaceList{"lan"},
						Source: model.Source{
							Network: "any",
						},
						Destination: model.Destination{
							Network: "lan",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid (self) reserved network",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface: model.InterfaceList{"wan"},
						Source: model.Source{
							Network: "any",
						},
						Destination: model.Destination{
							Network: "(self)",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid interface with ip suffix",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface: model.InterfaceList{"lan"},
						Source: model.Source{
							Network: "opt0ip",
						},
						Destination: model.Destination{
							Network: "wanip",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid CIDR",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface: model.InterfaceList{"lan"},
						Source: model.Source{
							Network: "192.168.1.0/24",
						},
						Destination: model.Destination{
							Network: "10.0.0.0/8",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid source network",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface: model.InterfaceList{"lan"},
						Source: model.Source{
							Network: "nonexistent",
						},
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].source.network",
		},
		{
			name: "invalid destination network",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface: model.InterfaceList{"lan"},
						Destination: model.Destination{
							Network: "nonexistent",
						},
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].destination.network",
		},
		{
			name: "invalid interface validation",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Interface: model.InterfaceList{"nonexistent"},
						Source: model.Source{
							Network: "any",
						},
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].interface",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateFilter(&tt.filter, interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")

			if tt.expectedErrors > 0 && len(errors) > 0 {
				assert.Equal(t, tt.errorField, errors[0].Field, "Expected error field")
			}
		})
	}
}

func TestValidateSystem_RequiredFields(t *testing.T) {
	tests := []struct {
		name           string
		system         model.System
		expectedErrors []string
	}{
		{
			name:   "missing hostname",
			system: model.System{Domain: "example.com"},
			expectedErrors: []string{
				"system.hostname",
			},
		},
		{
			name:   "missing domain",
			system: model.System{Hostname: "test"},
			expectedErrors: []string{
				"system.domain",
			},
		},
		{
			name: "invalid hostname",
			system: model.System{
				Hostname: "invalid-hostname-",
				Domain:   "example.com",
			},
			expectedErrors: []string{
				"system.hostname",
			},
		},
		{
			name: "invalid timezone",
			system: model.System{
				Hostname: "test",
				Domain:   "example.com",
				Timezone: "Invalid/Timezone",
			},
			expectedErrors: []string{
				"system.timezone",
			},
		},
		{
			name: "invalid optimization",
			system: model.System{
				Hostname:     "test",
				Domain:       "example.com",
				Optimization: "invalid",
			},
			expectedErrors: []string{
				"system.optimization",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateSystem(&tt.system)
			assert.Len(t, errors, len(tt.expectedErrors), "Expected number of errors")

			for i, expectedField := range tt.expectedErrors {
				assert.Equal(t, expectedField, errors[i].Field, "Expected field in error")
			}
		})
	}
}

func TestValidateInterface_IPAddressValidation(t *testing.T) {
	tests := []struct {
		name           string
		iface          model.Interface
		interfaceName  string
		expectedErrors int
	}{
		{
			name: "valid DHCP configuration",
			iface: model.Interface{
				IPAddr:   "dhcp",
				IPAddrv6: "dhcp6",
			},
			interfaceName:  "wan",
			expectedErrors: 0,
		},
		{
			name: "valid static IP configuration",
			iface: model.Interface{
				IPAddr: "192.168.1.1",
				Subnet: "24",
			},
			interfaceName:  "lan",
			expectedErrors: 0,
		},
		{
			name: "invalid IP address",
			iface: model.Interface{
				IPAddr: "invalid-ip",
			},
			interfaceName:  "lan",
			expectedErrors: 1,
		},
		{
			name: "invalid subnet mask",
			iface: model.Interface{
				IPAddr: "192.168.1.1",
				Subnet: "35", // Invalid subnet mask
			},
			interfaceName:  "lan",
			expectedErrors: 1,
		},
		{
			name: "valid track6 configuration",
			iface: model.Interface{
				IPAddrv6:        "track6",
				Track6Interface: "wan",
				Track6PrefixID:  "0",
			},
			interfaceName:  "lan",
			expectedErrors: 0,
		},
		{
			name: "incomplete track6 configuration",
			iface: model.Interface{
				IPAddrv6: "track6",
				// Missing Track6Interface and Track6PrefixID
			},
			interfaceName:  "lan",
			expectedErrors: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock interfaces structure for cross-field validation
			interfaces := &model.Interfaces{
				Items: map[string]model.Interface{
					"wan": {},
					"lan": {},
				},
			}
			errors := validateInterface(&tt.iface, tt.interfaceName, interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

func TestValidateFilter_RuleValidation(t *testing.T) {
	tests := []struct {
		name           string
		filter         model.Filter
		expectedErrors int
	}{
		{
			name: "valid filter rules",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  model.InterfaceList{"lan"},
						Source: model.Source{
							Network: "lan",
						},
					},
					{
						Type:       "block",
						IPProtocol: "inet6",
						Interface:  model.InterfaceList{"wan"},
						Source: model.Source{
							Network: "any",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid rule type",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Type:       "invalid",
						IPProtocol: "inet",
						Interface:  model.InterfaceList{"lan"},
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "invalid IP protocol",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Type:       "pass",
						IPProtocol: "invalid",
						Interface:  model.InterfaceList{"lan"},
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "invalid interface",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  model.InterfaceList{"invalid"},
					},
				},
			},
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock interfaces structure for the test
			interfaces := &model.Interfaces{
				Items: map[string]model.Interface{
					"wan": {},
					"lan": {},
				},
			}
			errors := validateFilter(&tt.filter, interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

func TestValidateDhcpd_RangeValidation(t *testing.T) {
	tests := []struct {
		name           string
		dhcpd          model.Dhcpd
		interfaces     model.Interfaces
		expectedErrors int
	}{
		{
			name: "valid DHCP range",
			dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"lan": {
						Range: model.Range{
							From: "192.168.1.100",
							To:   "192.168.1.199",
						},
					},
				},
			},
			interfaces: model.Interfaces{
				Items: map[string]model.Interface{
					"wan": {},
					"lan": {},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid from IP",
			dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"lan": {
						Range: model.Range{
							From: "invalid-ip",
							To:   "192.168.1.199",
						},
					},
				},
			},
			interfaces: model.Interfaces{
				Items: map[string]model.Interface{
					"wan": {},
					"lan": {},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "invalid range order",
			dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"lan": {
						Range: model.Range{
							From: "192.168.1.200",
							To:   "192.168.1.100",
						},
					},
				},
			},
			interfaces: model.Interfaces{
				Items: map[string]model.Interface{
					"wan": {},
					"lan": {},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "DHCP interface not in configured interfaces",
			dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"opt0": {
						Range: model.Range{
							From: "192.168.1.100",
							To:   "192.168.1.199",
						},
					},
				},
			},
			interfaces: model.Interfaces{
				Items: map[string]model.Interface{
					"wan": {},
					"lan": {},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "multiple interfaces validation",
			dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"lan": {
						Range: model.Range{
							From: "192.168.1.100",
							To:   "192.168.1.199",
						},
					},
					"opt0": {
						Range: model.Range{
							From: "10.0.0.100",
							To:   "10.0.0.199",
						},
					},
				},
			},
			interfaces: model.Interfaces{
				Items: map[string]model.Interface{
					"wan":  {},
					"lan":  {},
					"opt0": {},
				},
			},
			expectedErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateDhcpd(&tt.dhcpd, &tt.interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

func TestValidateUsersAndGroups_Uniqueness(t *testing.T) {
	system := model.System{
		Group: []model.Group{
			{Name: "admins", Gid: "1999", Scope: "system"},
			{Name: "admins", Gid: "2000", Scope: "system"}, // Duplicate name
			{Name: "users", Gid: "1999", Scope: "system"},  // Duplicate GID
		},
		User: []model.User{
			{Name: "root", UID: "0", Groupname: "admins", Scope: "system"},
			{Name: "root", UID: "1", Groupname: "admins", Scope: "system"},       // Duplicate name
			{Name: "user1", UID: "0", Groupname: "admins", Scope: "system"},      // Duplicate UID
			{Name: "user2", UID: "2", Groupname: "nonexistent", Scope: "system"}, // Invalid group
		},
	}

	errors := validateUsersAndGroups(&system)

	// Expected errors:
	// 1. Duplicate group name "admins"
	// 2. Duplicate group GID "1999"
	// 3. Duplicate user name "root"
	// 4. Duplicate user UID "0"
	// 5. Invalid group reference "nonexistent"
	assert.Len(t, errors, 5, "Expected 5 validation errors")
}

// TestValidationError_Error is already tested in config_test.go
// We don't duplicate it here to avoid redeclaration

func TestHelperFunctions(t *testing.T) {
	t.Run("contains", func(t *testing.T) {
		slice := []string{"a", "b", "c"}
		assert.True(t, contains(slice, "b"))
		assert.False(t, contains(slice, "d"))
	})

	t.Run("isValidHostname", func(t *testing.T) {
		assert.True(t, isValidHostname("test"))
		assert.True(t, isValidHostname("test-host"))
		assert.True(t, isValidHostname("test123"))
		assert.False(t, isValidHostname("test-"))
		assert.False(t, isValidHostname("-test"))
		assert.False(t, isValidHostname(""))
	})

	t.Run("isValidTimezone", func(t *testing.T) {
		assert.True(t, isValidTimezone("America/New_York"))
		assert.True(t, isValidTimezone("Etc/UTC"))
		assert.True(t, isValidTimezone("UTC"))
		assert.True(t, isValidTimezone("GMT+5"))
		assert.False(t, isValidTimezone("Invalid/Timezone"))
		assert.False(t, isValidTimezone("invalid"))
	})

	t.Run("isValidIP", func(t *testing.T) {
		assert.True(t, isValidIP("192.168.1.1"))
		assert.True(t, isValidIP("10.0.0.1"))
		assert.False(t, isValidIP("invalid-ip"))
		assert.False(t, isValidIP("256.1.1.1"))
		assert.False(t, isValidIP("2001:db8::1")) // IPv6 should be false for IPv4 validation
	})

	t.Run("isValidIPv6", func(t *testing.T) {
		assert.True(t, isValidIPv6("2001:db8::1"))
		assert.True(t, isValidIPv6("::1"))
		assert.False(t, isValidIPv6("192.168.1.1")) // IPv4 should be false for IPv6 validation
		assert.False(t, isValidIPv6("invalid-ipv6"))
	})

	t.Run("isValidCIDR", func(t *testing.T) {
		assert.True(t, isValidCIDR("192.168.1.0/24"))
		assert.True(t, isValidCIDR("10.0.0.0/8"))
		assert.True(t, isValidCIDR("2001:db8::/32"))
		assert.False(t, isValidCIDR("192.168.1.1"))
		assert.False(t, isValidCIDR("invalid-cidr"))
	})

	t.Run("isValidSysctlName", func(t *testing.T) {
		assert.True(t, isValidSysctlName("net.inet.ip.random_id"))
		assert.True(t, isValidSysctlName("kern.maxproc"))
		assert.False(t, isValidSysctlName("invalid"))
		assert.False(t, isValidSysctlName("123.invalid"))
		assert.False(t, isValidSysctlName(".invalid"))
	})
}

// TestValidateNat_ComprehensiveTests tests NAT validation with various modes.
func TestValidateNat_ComprehensiveTests(t *testing.T) {
	tests := []struct {
		name           string
		nat            model.Nat
		expectedErrors int
	}{
		{
			name: "valid automatic mode",
			nat: model.Nat{
				Outbound: model.Outbound{Mode: "automatic"},
			},
			expectedErrors: 0,
		},
		{
			name: "valid hybrid mode",
			nat: model.Nat{
				Outbound: model.Outbound{Mode: "hybrid"},
			},
			expectedErrors: 0,
		},
		{
			name: "valid advanced mode",
			nat: model.Nat{
				Outbound: model.Outbound{Mode: "advanced"},
			},
			expectedErrors: 0,
		},
		{
			name: "valid disabled mode",
			nat: model.Nat{
				Outbound: model.Outbound{Mode: "disabled"},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid mode",
			nat: model.Nat{
				Outbound: model.Outbound{Mode: "invalid-mode"},
			},
			expectedErrors: 1,
		},
		{
			name: "empty mode (should be valid)",
			nat: model.Nat{
				Outbound: model.Outbound{Mode: ""},
			},
			expectedErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateNat(&tt.nat)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

// TestValidateSystem_PowerManagement tests power management validation.
func TestValidateSystem_PowerManagement(t *testing.T) {
	tests := []struct {
		name           string
		system         model.System
		expectedErrors int
	}{
		{
			name: "valid power modes",
			system: model.System{
				Hostname:          "test",
				Domain:            "test.local",
				PowerdACMode:      "hadp",
				PowerdBatteryMode: "hiadp",
				PowerdNormalMode:  "adaptive",
			},
			expectedErrors: 0,
		},
		{
			name: "invalid AC power mode",
			system: model.System{
				Hostname:     "test",
				Domain:       "test.local",
				PowerdACMode: "invalid",
			},
			expectedErrors: 1,
		},
		{
			name: "invalid battery power mode",
			system: model.System{
				Hostname:          "test",
				Domain:            "test.local",
				PowerdBatteryMode: "invalid",
			},
			expectedErrors: 1,
		},
		{
			name: "invalid normal power mode",
			system: model.System{
				Hostname:         "test",
				Domain:           "test.local",
				PowerdNormalMode: "invalid",
			},
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateSystem(&tt.system)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

// TestValidateSystem_BogonsInterval tests bogons interval validation.
func TestValidateSystem_BogonsInterval(t *testing.T) {
	tests := []struct {
		name           string
		system         model.System
		expectedErrors int
	}{
		{
			name: "valid bogons intervals",
			system: model.System{
				Hostname: "test",
				Domain:   "test.local",
				Bogons: struct {
					Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
				}{Interval: "monthly"},
			},
			expectedErrors: 0,
		},
		{
			name: "valid weekly interval",
			system: model.System{
				Hostname: "test",
				Domain:   "test.local",
				Bogons: struct {
					Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
				}{Interval: "weekly"},
			},
			expectedErrors: 0,
		},
		{
			name: "valid daily interval",
			system: model.System{
				Hostname: "test",
				Domain:   "test.local",
				Bogons: struct {
					Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
				}{Interval: "daily"},
			},
			expectedErrors: 0,
		},
		{
			name: "valid never interval",
			system: model.System{
				Hostname: "test",
				Domain:   "test.local",
				Bogons: struct {
					Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
				}{Interval: "never"},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid bogons interval",
			system: model.System{
				Hostname: "test",
				Domain:   "test.local",
				Bogons: struct {
					Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
				}{Interval: "invalid"},
			},
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateSystem(&tt.system)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

// TestValidateInterface_MTUValidation tests MTU validation.
func TestValidateInterface_MTUValidation(t *testing.T) {
	tests := []struct {
		name           string
		iface          model.Interface
		expectedErrors int
	}{
		{
			name: "valid MTU",
			iface: model.Interface{
				MTU: "1500",
			},
			expectedErrors: 0,
		},
		{
			name: "minimum valid MTU",
			iface: model.Interface{
				MTU: "68",
			},
			expectedErrors: 0,
		},
		{
			name: "maximum valid MTU",
			iface: model.Interface{
				MTU: "9000",
			},
			expectedErrors: 0,
		},
		{
			name: "MTU too low",
			iface: model.Interface{
				MTU: "67",
			},
			expectedErrors: 1,
		},
		{
			name: "MTU too high",
			iface: model.Interface{
				MTU: "9001",
			},
			expectedErrors: 1,
		},
		{
			name: "invalid MTU format",
			iface: model.Interface{
				MTU: "invalid",
			},
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock interfaces structure for cross-field validation
			interfaces := &model.Interfaces{
				Items: map[string]model.Interface{
					"test": {},
				},
			}
			errors := validateInterface(&tt.iface, "test", interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

// TestValidateFilter_SourceNetworkValidation tests source network validation with CIDR.
func TestValidateFilter_SourceNetworkValidation(t *testing.T) {
	tests := []struct {
		name           string
		filter         model.Filter
		expectedErrors int
	}{
		{
			name: "valid CIDR source network",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  model.InterfaceList{"lan"},
						Source: model.Source{
							Network: "192.168.1.0/24",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid IPv6 CIDR source network",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet6",
						Interface:  model.InterfaceList{"lan"},
						Source: model.Source{
							Network: "2001:db8::/32",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid CIDR source network",
			filter: model.Filter{
				Rule: []model.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  model.InterfaceList{"lan"},
						Source: model.Source{
							Network: "invalid-cidr",
						},
					},
				},
			},
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock interfaces structure for the test
			interfaces := &model.Interfaces{
				Items: map[string]model.Interface{
					"lan": {},
				},
			}
			errors := validateFilter(&tt.filter, interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}
