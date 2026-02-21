package validator

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateOpnSenseDocument_ValidConfig(t *testing.T) {
	config := &schema.OpnSenseDocument{
		System: schema.System{
			Hostname:          "test-host",
			Domain:            "test.local",
			Timezone:          "Etc/UTC",
			Optimization:      "normal",
			WebGUI:            schema.WebGUIConfig{Protocol: "https"},
			PowerdACMode:      "hadp",
			PowerdBatteryMode: "hadp",
			PowerdNormalMode:  "hadp",
			Bogons: struct {
				Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
			}{Interval: "monthly"},
			Group: []schema.Group{
				{
					Name:  "admins",
					Gid:   "1999",
					Scope: "system",
				},
			},
			User: []schema.User{
				{
					Name:      "root",
					UID:       "0",
					Groupname: "admins",
					Scope:     "system",
				},
			},
		},
		Interfaces: schema.Interfaces{
			Items: map[string]schema.Interface{
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
		Dhcpd: schema.Dhcpd{
			Items: map[string]schema.DhcpdInterface{
				"lan": {
					Range: schema.Range{
						From: "192.168.1.100",
						To:   "192.168.1.199",
					},
				},
			},
		},
		Filter: schema.Filter{
			Rule: []schema.Rule{
				{
					Type:       "pass",
					IPProtocol: "inet",
					Interface:  schema.InterfaceList{"lan"},
					Source: schema.Source{
						Network: "lan",
					},
					Destination: schema.Destination{
						Network: "opt0ip",
					},
				},
			},
		},
		Nat: schema.Nat{
			Outbound: schema.Outbound{
				Mode: "automatic",
			},
		},
		Sysctl: []schema.SysctlItem{
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
	interfaces := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"wan":  {},
			"lan":  {},
			"opt0": {},
		},
	}

	tests := []struct {
		name           string
		filter         schema.Filter
		expectedErrors int
		errorField     string
	}{
		{
			name: "valid reserved network",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Interface: schema.InterfaceList{"lan"},
						Source: schema.Source{
							Network: "any",
						},
						Destination: schema.Destination{
							Network: "lan",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid (self) reserved network",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Interface: schema.InterfaceList{"wan"},
						Source: schema.Source{
							Network: "any",
						},
						Destination: schema.Destination{
							Network: "(self)",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid interface with ip suffix",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Interface: schema.InterfaceList{"lan"},
						Source: schema.Source{
							Network: "opt0ip",
						},
						Destination: schema.Destination{
							Network: "wanip",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid CIDR",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Interface: schema.InterfaceList{"lan"},
						Source: schema.Source{
							Network: "192.168.1.0/24",
						},
						Destination: schema.Destination{
							Network: "10.0.0.0/8",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid source network",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Interface: schema.InterfaceList{"lan"},
						Source: schema.Source{
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
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Interface: schema.InterfaceList{"lan"},
						Destination: schema.Destination{
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
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Interface: schema.InterfaceList{"nonexistent"},
						Source: schema.Source{
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
		system         schema.System
		expectedErrors []string
	}{
		{
			name:   "missing hostname",
			system: schema.System{Domain: "example.com"},
			expectedErrors: []string{
				"system.hostname",
			},
		},
		{
			name:   "missing domain",
			system: schema.System{Hostname: "test"},
			expectedErrors: []string{
				"system.domain",
			},
		},
		{
			name: "invalid hostname",
			system: schema.System{
				Hostname: "invalid-hostname-",
				Domain:   "example.com",
			},
			expectedErrors: []string{
				"system.hostname",
			},
		},
		{
			name: "invalid timezone",
			system: schema.System{
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
			system: schema.System{
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
		iface          schema.Interface
		interfaceName  string
		expectedErrors int
	}{
		{
			name: "valid DHCP configuration",
			iface: schema.Interface{
				IPAddr:   "dhcp",
				IPAddrv6: "dhcp6",
			},
			interfaceName:  "wan",
			expectedErrors: 0,
		},
		{
			name: "valid static IP configuration",
			iface: schema.Interface{
				IPAddr: "192.168.1.1",
				Subnet: "24",
			},
			interfaceName:  "lan",
			expectedErrors: 0,
		},
		{
			name: "invalid IP address",
			iface: schema.Interface{
				IPAddr: "invalid-ip",
			},
			interfaceName:  "lan",
			expectedErrors: 1,
		},
		{
			name: "invalid subnet mask",
			iface: schema.Interface{
				IPAddr: "192.168.1.1",
				Subnet: "35", // Invalid subnet mask
			},
			interfaceName:  "lan",
			expectedErrors: 1,
		},
		{
			name: "valid track6 configuration",
			iface: schema.Interface{
				IPAddrv6:        "track6",
				Track6Interface: "wan",
				Track6PrefixID:  "0",
			},
			interfaceName:  "lan",
			expectedErrors: 0,
		},
		{
			name: "incomplete track6 configuration",
			iface: schema.Interface{
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
			interfaces := &schema.Interfaces{
				Items: map[string]schema.Interface{
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
		filter         schema.Filter
		expectedErrors int
	}{
		{
			name: "valid filter rules",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  schema.InterfaceList{"lan"},
						Source: schema.Source{
							Network: "lan",
						},
					},
					{
						Type:       "block",
						IPProtocol: "inet6",
						Interface:  schema.InterfaceList{"wan"},
						Source: schema.Source{
							Network: "any",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid rule type",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:       "invalid",
						IPProtocol: "inet",
						Interface:  schema.InterfaceList{"lan"},
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "invalid IP protocol",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:       "pass",
						IPProtocol: "invalid",
						Interface:  schema.InterfaceList{"lan"},
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "invalid interface",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  schema.InterfaceList{"invalid"},
					},
				},
			},
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock interfaces structure for the test
			interfaces := &schema.Interfaces{
				Items: map[string]schema.Interface{
					"wan": {},
					"lan": {},
				},
			}
			errors := validateFilter(&tt.filter, interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

func TestValidateFilter_AddressValidation(t *testing.T) {
	tests := []struct {
		name           string
		filter         schema.Filter
		expectedErrors int
	}{
		{
			name: "valid source address (IP)",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  schema.InterfaceList{"lan"},
						Source:     schema.Source{Address: "192.168.1.100"},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid source address (CIDR)",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  schema.InterfaceList{"lan"},
						Source:     schema.Source{Address: "10.0.0.0/8"},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid source address (alias)",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  schema.InterfaceList{"lan"},
						Source:     schema.Source{Address: "WebServers"},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "malformed source address (invalid CIDR)",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  schema.InterfaceList{"lan"},
						Source:     schema.Source{Address: "192.168.1.0/33"},
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "malformed destination address (invalid IP)",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:        "pass",
						IPProtocol:  "inet",
						Interface:   schema.InterfaceList{"lan"},
						Destination: schema.Destination{Address: "999.999.999.999"},
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "valid destination address (alias)",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:        "pass",
						IPProtocol:  "inet",
						Interface:   schema.InterfaceList{"lan"},
						Destination: schema.Destination{Address: "MailServers"},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid source address (dotted alias)",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  schema.InterfaceList{"lan"},
						Source:     schema.Source{Address: "internal.servers"},
					},
				},
			},
			expectedErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interfaces := &schema.Interfaces{
				Items: map[string]schema.Interface{
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
		dhcpd          schema.Dhcpd
		interfaces     schema.Interfaces
		expectedErrors int
	}{
		{
			name: "valid DHCP range",
			dhcpd: schema.Dhcpd{
				Items: map[string]schema.DhcpdInterface{
					"lan": {
						Range: schema.Range{
							From: "192.168.1.100",
							To:   "192.168.1.199",
						},
					},
				},
			},
			interfaces: schema.Interfaces{
				Items: map[string]schema.Interface{
					"wan": {},
					"lan": {},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid from IP",
			dhcpd: schema.Dhcpd{
				Items: map[string]schema.DhcpdInterface{
					"lan": {
						Range: schema.Range{
							From: "invalid-ip",
							To:   "192.168.1.199",
						},
					},
				},
			},
			interfaces: schema.Interfaces{
				Items: map[string]schema.Interface{
					"wan": {},
					"lan": {},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "invalid range order",
			dhcpd: schema.Dhcpd{
				Items: map[string]schema.DhcpdInterface{
					"lan": {
						Range: schema.Range{
							From: "192.168.1.200",
							To:   "192.168.1.100",
						},
					},
				},
			},
			interfaces: schema.Interfaces{
				Items: map[string]schema.Interface{
					"wan": {},
					"lan": {},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "DHCP interface not in configured interfaces",
			dhcpd: schema.Dhcpd{
				Items: map[string]schema.DhcpdInterface{
					"opt0": {
						Range: schema.Range{
							From: "192.168.1.100",
							To:   "192.168.1.199",
						},
					},
				},
			},
			interfaces: schema.Interfaces{
				Items: map[string]schema.Interface{
					"wan": {},
					"lan": {},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "multiple interfaces validation",
			dhcpd: schema.Dhcpd{
				Items: map[string]schema.DhcpdInterface{
					"lan": {
						Range: schema.Range{
							From: "192.168.1.100",
							To:   "192.168.1.199",
						},
					},
					"opt0": {
						Range: schema.Range{
							From: "10.0.0.100",
							To:   "10.0.0.199",
						},
					},
				},
			},
			interfaces: schema.Interfaces{
				Items: map[string]schema.Interface{
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
	system := schema.System{
		Group: []schema.Group{
			{Name: "admins", Gid: "1999", Scope: "system"},
			{Name: "admins", Gid: "2000", Scope: "system"}, // Duplicate name
			{Name: "users", Gid: "1999", Scope: "system"},  // Duplicate GID
		},
		User: []schema.User{
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
		nat            schema.Nat
		expectedErrors int
	}{
		{
			name: "valid automatic mode",
			nat: schema.Nat{
				Outbound: schema.Outbound{Mode: "automatic"},
			},
			expectedErrors: 0,
		},
		{
			name: "valid hybrid mode",
			nat: schema.Nat{
				Outbound: schema.Outbound{Mode: "hybrid"},
			},
			expectedErrors: 0,
		},
		{
			name: "valid advanced mode",
			nat: schema.Nat{
				Outbound: schema.Outbound{Mode: "advanced"},
			},
			expectedErrors: 0,
		},
		{
			name: "valid disabled mode",
			nat: schema.Nat{
				Outbound: schema.Outbound{Mode: "disabled"},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid mode",
			nat: schema.Nat{
				Outbound: schema.Outbound{Mode: "invalid-mode"},
			},
			expectedErrors: 1,
		},
		{
			name: "empty mode (should be valid)",
			nat: schema.Nat{
				Outbound: schema.Outbound{Mode: ""},
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
		system         schema.System
		expectedErrors int
	}{
		{
			name: "valid power modes",
			system: schema.System{
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
			system: schema.System{
				Hostname:     "test",
				Domain:       "test.local",
				PowerdACMode: "invalid",
			},
			expectedErrors: 1,
		},
		{
			name: "invalid battery power mode",
			system: schema.System{
				Hostname:          "test",
				Domain:            "test.local",
				PowerdBatteryMode: "invalid",
			},
			expectedErrors: 1,
		},
		{
			name: "invalid normal power mode",
			system: schema.System{
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
		system         schema.System
		expectedErrors int
	}{
		{
			name: "valid bogons intervals",
			system: schema.System{
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
			system: schema.System{
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
			system: schema.System{
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
			system: schema.System{
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
			system: schema.System{
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
		iface          schema.Interface
		expectedErrors int
	}{
		{
			name: "valid MTU",
			iface: schema.Interface{
				MTU: "1500",
			},
			expectedErrors: 0,
		},
		{
			name: "minimum valid MTU",
			iface: schema.Interface{
				MTU: "68",
			},
			expectedErrors: 0,
		},
		{
			name: "maximum valid MTU",
			iface: schema.Interface{
				MTU: "9000",
			},
			expectedErrors: 0,
		},
		{
			name: "MTU too low",
			iface: schema.Interface{
				MTU: "67",
			},
			expectedErrors: 1,
		},
		{
			name: "MTU too high",
			iface: schema.Interface{
				MTU: "9001",
			},
			expectedErrors: 1,
		},
		{
			name: "invalid MTU format",
			iface: schema.Interface{
				MTU: "invalid",
			},
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock interfaces structure for cross-field validation
			interfaces := &schema.Interfaces{
				Items: map[string]schema.Interface{
					"test": {},
				},
			}
			errors := validateInterface(&tt.iface, "test", interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

// TestValidateFilter_MutualExclusivity tests that source/destination fields are mutually exclusive.
func TestValidateFilter_MutualExclusivity(t *testing.T) {
	interfaces := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"wan": {},
			"lan": {},
		},
	}

	tests := []struct {
		name           string
		filter         schema.Filter
		expectedErrors int
		errorField     string
	}{
		{
			name: "source with only any - valid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"lan"},
						Source:    schema.Source{Any: new("")},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "source with only network - valid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"lan"},
						Source:    schema.Source{Network: "lan"},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "source with only address - valid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"lan"},
						Source:    schema.Source{Address: "192.168.1.100"},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "source with any and network - invalid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"lan"},
						Source:    schema.Source{Any: new(""), Network: "lan"},
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].source",
		},
		{
			name: "source with any and address - invalid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"lan"},
						Source:    schema.Source{Any: new(""), Address: "10.0.0.1"},
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].source",
		},
		{
			name: "source with network and address - invalid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"lan"},
						Source:    schema.Source{Network: "lan", Address: "10.0.0.1"},
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].source",
		},
		{
			name: "destination with any and network - invalid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:        "pass",
						Interface:   schema.InterfaceList{"lan"},
						Destination: schema.Destination{Any: new(""), Network: "wan"},
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].destination",
		},
		{
			name: "destination with any and address - invalid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:        "pass",
						Interface:   schema.InterfaceList{"lan"},
						Destination: schema.Destination{Any: new(""), Address: "10.0.0.1"},
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].destination",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateFilter(&tt.filter, interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
			if tt.expectedErrors > 0 && len(errors) > 0 {
				assert.Equal(t, tt.errorField, errors[0].Field)
			}
		})
	}
}

// TestValidateFilter_FloatingRuleConstraints tests floating rule direction validation.
func TestValidateFilter_FloatingRuleConstraints(t *testing.T) {
	interfaces := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"wan": {},
			"lan": {},
		},
	}

	tests := []struct {
		name           string
		filter         schema.Filter
		expectedErrors int
		errorField     string
	}{
		{
			name: "floating rule with direction - valid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"wan", "lan"},
						Floating:  "yes",
						Direction: "any",
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "floating rule without direction - invalid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"wan"},
						Floating:  "yes",
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].direction",
		},
		{
			name: "floating rule with invalid direction",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"wan"},
						Floating:  "yes",
						Direction: "invalid",
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].direction",
		},
		{
			name: "non-floating rule with direction in - valid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"lan"},
						Direction: "in",
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "non-floating rule with invalid direction",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"lan"},
						Direction: "sideways",
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].direction",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateFilter(&tt.filter, interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
			if tt.expectedErrors > 0 && len(errors) > 0 {
				assert.Equal(t, tt.errorField, errors[0].Field)
			}
		})
	}
}

// TestValidateFilter_StateTypeValidation tests state type validation.
//
//nolint:dupl // table-driven test structure intentionally similar to MaxSrcConnRateFormat
func TestValidateFilter_StateTypeValidation(t *testing.T) {
	interfaces := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"lan": {},
		},
	}

	tests := []struct {
		name           string
		filter         schema.Filter
		expectedErrors int
	}{
		{
			name: "valid keep state",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{Type: "pass", Interface: schema.InterfaceList{"lan"}, StateType: "keep state"},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid sloppy state",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{Type: "pass", Interface: schema.InterfaceList{"lan"}, StateType: "sloppy state"},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid synproxy state",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{Type: "pass", Interface: schema.InterfaceList{"lan"}, StateType: "synproxy state"},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid none",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{Type: "pass", Interface: schema.InterfaceList{"lan"}, StateType: "none"},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "empty state type - valid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{Type: "pass", Interface: schema.InterfaceList{"lan"}, StateType: ""},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid state type",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{Type: "pass", Interface: schema.InterfaceList{"lan"}, StateType: "invalid"},
				},
			},
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateFilter(&tt.filter, interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

// TestValidateFilter_MaxSrcConnRateFormat tests rate-limiting field format validation.
//
//nolint:dupl // table-driven test structure intentionally similar to StateTypeValidation
func TestValidateFilter_MaxSrcConnRateFormat(t *testing.T) {
	interfaces := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"lan": {},
		},
	}

	tests := []struct {
		name           string
		filter         schema.Filter
		expectedErrors int
	}{
		{
			name: "valid rate format 15/5",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{Type: "pass", Interface: schema.InterfaceList{"lan"}, MaxSrcConnRate: "15/5"},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid rate format 100/60",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{Type: "pass", Interface: schema.InterfaceList{"lan"}, MaxSrcConnRate: "100/60"},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "empty rate - valid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{Type: "pass", Interface: schema.InterfaceList{"lan"}, MaxSrcConnRate: ""},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid rate format - no slash",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{Type: "pass", Interface: schema.InterfaceList{"lan"}, MaxSrcConnRate: "15"},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "invalid rate format - non-numeric",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{Type: "pass", Interface: schema.InterfaceList{"lan"}, MaxSrcConnRate: "abc/def"},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "invalid rate format - extra slash",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{Type: "pass", Interface: schema.InterfaceList{"lan"}, MaxSrcConnRate: "15/5/3"},
				},
			},
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateFilter(&tt.filter, interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

// TestValidateNat_InboundReflection tests NAT reflection mode validation.
func TestValidateNat_InboundReflection(t *testing.T) {
	tests := []struct {
		name           string
		nat            schema.Nat
		expectedErrors int
	}{
		{
			name: "valid reflection enable",
			nat: schema.Nat{
				Inbound: []schema.InboundRule{
					{NATReflection: "enable"},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid reflection disable",
			nat: schema.Nat{
				Inbound: []schema.InboundRule{
					{NATReflection: "disable"},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid reflection purenat",
			nat: schema.Nat{
				Inbound: []schema.InboundRule{
					{NATReflection: "purenat"},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "empty reflection - valid",
			nat: schema.Nat{
				Inbound: []schema.InboundRule{
					{NATReflection: ""},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid reflection mode",
			nat: schema.Nat{
				Inbound: []schema.InboundRule{
					{NATReflection: "invalid"},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "multiple inbound rules mixed validity",
			nat: schema.Nat{
				Inbound: []schema.InboundRule{
					{NATReflection: "enable"},
					{NATReflection: "badmode"},
					{NATReflection: "purenat"},
				},
			},
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateNat(&tt.nat)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

// TestIsValidPortOrRange tests the port validation helper directly.
func TestIsValidPortOrRange(t *testing.T) {
	tests := []struct {
		name  string
		port  string
		valid bool
	}{
		{name: "empty value", port: "", valid: true},
		{name: "single valid port 80", port: "80", valid: true},
		{name: "single valid port 443", port: "443", valid: true},
		{name: "single valid port 1", port: "1", valid: true},
		{name: "single valid port 65535", port: "65535", valid: true},
		{name: "valid range 1024-65535", port: "1024-65535", valid: true},
		{name: "valid range 80-443", port: "80-443", valid: true},
		{name: "valid range same value", port: "443-443", valid: true},
		{name: "alias name http", port: "http", valid: true},
		{name: "alias name MyAlias", port: "MyAlias", valid: true},
		{name: "alias name with underscore", port: "web_servers", valid: true},
		{name: "invalid port zero", port: "0", valid: false},
		{name: "invalid port 65536", port: "65536", valid: false},
		{name: "invalid port 99999", port: "99999", valid: false},
		{name: "inverted range 443-80", port: "443-80", valid: false},
		{name: "inverted range 65535-1", port: "65535-1", valid: false},
		{name: "malformed 80-abc", port: "80-abc", valid: false},
		{name: "range with zero low", port: "0-80", valid: false},
		{name: "range with zero high", port: "80-0", valid: false},
		{name: "range exceeds max", port: "1-65536", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPortOrRange(tt.port)
			assert.Equal(t, tt.valid, result, "port: %q", tt.port)
		})
	}
}

// TestValidateFilter_PortValidation tests port validation for source and destination in filter rules.
func TestValidateFilter_PortValidation(t *testing.T) {
	interfaces := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"lan": {},
		},
	}

	tests := []struct {
		name           string
		filter         schema.Filter
		expectedErrors int
		errorField     string
	}{
		{
			name: "valid source port 443",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"lan"},
						Source:    schema.Source{Any: new(""), Port: "443"},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid destination port 80",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:        "pass",
						Interface:   schema.InterfaceList{"lan"},
						Destination: schema.Destination{Any: new(""), Port: "80"},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid source port range",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"lan"},
						Source:    schema.Source{Any: new(""), Port: "1024-65535"},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid destination port alias",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:        "pass",
						Interface:   schema.InterfaceList{"lan"},
						Destination: schema.Destination{Any: new(""), Port: "http"},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "empty ports - valid",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:        "pass",
						Interface:   schema.InterfaceList{"lan"},
						Source:      schema.Source{Any: new("")},
						Destination: schema.Destination{Any: new("")},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid source port zero",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"lan"},
						Source:    schema.Source{Any: new(""), Port: "0"},
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].source.port",
		},
		{
			name: "invalid destination port 65536",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:        "pass",
						Interface:   schema.InterfaceList{"lan"},
						Destination: schema.Destination{Any: new(""), Port: "65536"},
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].destination.port",
		},
		{
			name: "invalid source inverted range",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:      "pass",
						Interface: schema.InterfaceList{"lan"},
						Source:    schema.Source{Any: new(""), Port: "443-80"},
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].source.port",
		},
		{
			name: "invalid destination malformed 80-abc",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:        "pass",
						Interface:   schema.InterfaceList{"lan"},
						Destination: schema.Destination{Any: new(""), Port: "80-abc"},
					},
				},
			},
			expectedErrors: 1,
			errorField:     "filter.rule[0].destination.port",
		},
		{
			name: "both source and destination invalid ports",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:        "pass",
						Interface:   schema.InterfaceList{"lan"},
						Source:      schema.Source{Any: new(""), Port: "0"},
						Destination: schema.Destination{Any: new(""), Port: "65536"},
					},
				},
			},
			expectedErrors: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateFilter(&tt.filter, interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
			if tt.expectedErrors == 1 && len(errors) > 0 && tt.errorField != "" {
				assert.Equal(t, tt.errorField, errors[0].Field)
			}
		})
	}
}

// TestValidateFilter_SourceNetworkValidation tests source network validation with CIDR.
func TestValidateFilter_SourceNetworkValidation(t *testing.T) {
	tests := []struct {
		name           string
		filter         schema.Filter
		expectedErrors int
	}{
		{
			name: "valid CIDR source network",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  schema.InterfaceList{"lan"},
						Source: schema.Source{
							Network: "192.168.1.0/24",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "valid IPv6 CIDR source network",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet6",
						Interface:  schema.InterfaceList{"lan"},
						Source: schema.Source{
							Network: "2001:db8::/32",
						},
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid CIDR source network",
			filter: schema.Filter{
				Rule: []schema.Rule{
					{
						Type:       "pass",
						IPProtocol: "inet",
						Interface:  schema.InterfaceList{"lan"},
						Source: schema.Source{
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
			interfaces := &schema.Interfaces{
				Items: map[string]schema.Interface{
					"lan": {},
				},
			}
			errors := validateFilter(&tt.filter, interfaces)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

func TestValidateOpnSenseDocument_NilDocument(t *testing.T) {
	t.Parallel()

	errors := ValidateOpnSenseDocument(nil)
	require.Len(t, errors, 1)
	assert.Equal(t, "document", errors[0].Field)
	assert.Contains(t, errors[0].Message, "nil")
}

func TestIsValidConnRateFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rate string
		want bool
	}{
		{"valid rate", "15/5", true},
		{"valid high rate", "100/60", true},
		{"zero connections", "0/5", false},
		{"zero seconds", "15/0", false},
		{"both zero", "0/0", false},
		{"empty string", "", false},
		{"no slash", "155", false},
		{"letters", "abc/def", false},
		{"negative", "-1/5", false},
		{"decimal", "1.5/5", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isValidConnRateFormat(tt.rate)
			assert.Equal(t, tt.want, got, "isValidConnRateFormat(%q)", tt.rate)
		})
	}
}
