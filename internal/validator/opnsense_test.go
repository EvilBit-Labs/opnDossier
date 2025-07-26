package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/unclesp1d3r/opnFocus/internal/model"
)

func TestValidateOpnsense_ValidConfig(t *testing.T) {
	config := &model.Opnsense{
		System: model.System{
			Hostname:     "OPNsense",
			Domain:       "localdomain",
			Timezone:     "Etc/UTC",
			Optimization: "normal",
			Webgui: model.Webgui{
				Protocol: "https",
			},
			PowerdAcMode:      "hadp",
			PowerdBatteryMode: "hadp",
			PowerdNormalMode:  "hadp",
			Bogons: model.Bogons{
				Interval: "monthly",
			},
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
			Wan: model.Interface{
				IPAddr:   "dhcp",
				IPAddrv6: "dhcp6",
			},
			Lan: model.Interface{
				IPAddr:          "192.168.1.1",
				Subnet:          "24",
				IPAddrv6:        "track6",
				Subnetv6:        "64",
				Track6Interface: "wan",
				Track6PrefixID:  "0",
			},
		},
		Dhcpd: model.Dhcpd{
			Lan: model.DhcpdInterface{
				Range: model.Range{
					From: "192.168.1.100",
					To:   "192.168.1.199",
				},
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{
					Type:       "pass",
					IPProtocol: "inet",
					Interface:  "lan",
					Source: model.Source{
						Network: "lan",
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

	errors := ValidateOpnsense(config)
	assert.Empty(t, errors, "Valid configuration should not produce validation errors")
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
			errors := validateInterface(&tt.iface, tt.interfaceName)
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
						Interface:  "lan",
						Source: model.Source{
							Network: "lan",
						},
					},
					{
						Type:       "block",
						IPProtocol: "inet6",
						Interface:  "wan",
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
						Interface:  "lan",
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
						Interface:  "lan",
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
						Interface:  "invalid",
					},
				},
			},
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateFilter(&tt.filter)
			assert.Len(t, errors, tt.expectedErrors, "Expected number of errors")
		})
	}
}

func TestValidateDhcpd_RangeValidation(t *testing.T) {
	tests := []struct {
		name           string
		dhcpd          model.Dhcpd
		expectedErrors int
	}{
		{
			name: "valid DHCP range",
			dhcpd: model.Dhcpd{
				Lan: model.DhcpdInterface{
					Range: model.Range{
						From: "192.168.1.100",
						To:   "192.168.1.199",
					},
				},
			},
			expectedErrors: 0,
		},
		{
			name: "invalid from IP",
			dhcpd: model.Dhcpd{
				Lan: model.DhcpdInterface{
					Range: model.Range{
						From: "invalid-ip",
						To:   "192.168.1.199",
					},
				},
			},
			expectedErrors: 1,
		},
		{
			name: "invalid range order",
			dhcpd: model.Dhcpd{
				Lan: model.DhcpdInterface{
					Range: model.Range{
						From: "192.168.1.200",
						To:   "192.168.1.100",
					},
				},
			},
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validateDhcpd(&tt.dhcpd)
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
