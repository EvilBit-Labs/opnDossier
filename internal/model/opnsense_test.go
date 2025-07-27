package model

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpnsenseModel_XMLUnmarshalling(t *testing.T) {
	// Test that XML unmarshalling still works with the refactored model
	xmlData := `<opnsense>
		<version>1.2.3</version>
		<theme>opnsense</theme>
		<system>
			<hostname>test-host</hostname>
			<domain>test.local</domain>
		</system>
		<interfaces>
			<wan>
				<if>em0</if>
				<ipaddr>dhcp</ipaddr>
			</wan>
			<lan>
				<if>em1</if>
				<ipaddr>192.168.1.1</ipaddr>
				<subnet>24</subnet>
			</lan>
		</interfaces>
		<nat>
			<outbound>
				<mode>automatic</mode>
			</outbound>
		</nat>
		<filter>
			<rule>
				<type>pass</type>
				<ipprotocol>inet</ipprotocol>
				<descr>Test rule</descr>
				<interface>lan</interface>
				<source>
					<network>lan</network>
				</source>
				<destination>
					<any/>
				</destination>
			</rule>
		</filter>
		<sysctl>
			<descr>Test sysctl</descr>
			<tunable>net.inet.ip.test</tunable>
			<value>1</value>
		</sysctl>
	</opnsense>`

	var opnsense Opnsense
	err := xml.Unmarshal([]byte(xmlData), &opnsense)
	require.NoError(t, err)

	// Test basic fields
	assert.Equal(t, "1.2.3", opnsense.Version)
	assert.Equal(t, "opnsense", opnsense.Theme)
	assert.Equal(t, "test-host", opnsense.System.Hostname)
	assert.Equal(t, "test.local", opnsense.System.Domain)

	// Test interfaces
	wan, exists := opnsense.Interfaces.Items["wan"]
	assert.True(t, exists)
	assert.Equal(t, "em0", wan.If)
	assert.Equal(t, "dhcp", wan.IPAddr)

	lan, exists := opnsense.Interfaces.Items["lan"]
	assert.True(t, exists)
	assert.Equal(t, "em1", lan.If)
	assert.Equal(t, "192.168.1.1", lan.IPAddr)
	assert.Equal(t, "24", lan.Subnet)

	// Test NAT configuration
	assert.Equal(t, "automatic", opnsense.Nat.Outbound.Mode)

	// Test firewall rules
	require.Len(t, opnsense.Filter.Rule, 1)
	rule := opnsense.Filter.Rule[0]
	assert.Equal(t, "pass", rule.Type)
	assert.Equal(t, "inet", rule.IPProtocol)
	assert.Equal(t, "Test rule", rule.Descr)
	assert.Equal(t, "lan", rule.Interface)
	assert.Equal(t, "lan", rule.Source.Network)

	// Test sysctl
	require.Len(t, opnsense.Sysctl, 1)
	sysctl := opnsense.Sysctl[0]
	assert.Equal(t, "Test sysctl", sysctl.Descr)
	assert.Equal(t, "net.inet.ip.test", sysctl.Tunable)
	assert.Equal(t, "1", sysctl.Value)
}

func TestOpnsenseModel_HelperMethods(t *testing.T) {
	opnsense := Opnsense{
		System: System{
			Hostname: "test-hostname",
		},
		Interfaces: Interfaces{
			Items: map[string]Interface{
				"wan": {If: "em0"},
				"lan": {If: "em1"},
			},
		},
		Filter: Filter{
			Rule: []Rule{
				{Type: "pass", Descr: "Test rule 1"},
				{Type: "block", Descr: "Test rule 2"},
			},
		},
	}

	// Test Hostname helper
	assert.Equal(t, "test-hostname", opnsense.Hostname())

	// Test InterfaceByName helper
	wanInterface := opnsense.InterfaceByName("em0")
	require.NotNil(t, wanInterface)
	assert.Equal(t, "em0", wanInterface.If)

	lanInterface := opnsense.InterfaceByName("em1")
	require.NotNil(t, lanInterface)
	assert.Equal(t, "em1", lanInterface.If)

	nonExistentInterface := opnsense.InterfaceByName("em2")
	assert.Nil(t, nonExistentInterface)

	// Test FilterRules helper
	rules := opnsense.FilterRules()
	require.Len(t, rules, 2)
	assert.Equal(t, "Test rule 1", rules[0].Descr)
	assert.Equal(t, "Test rule 2", rules[1].Descr)
}

func TestOpnsenseModel_ConfigGroupHelpers(t *testing.T) {
	opnsense := Opnsense{
		System: System{
			Hostname: "test-hostname",
			Domain:   "test.local",
		},
		Sysctl: []SysctlItem{
			{Tunable: "net.inet.ip.test", Value: "1"},
		},
		Interfaces: Interfaces{
			Items: map[string]Interface{
				"wan": {If: "em0"},
				"lan": {If: "em1"},
			},
		},
		Nat:    Nat{Outbound: Outbound{Mode: "automatic"}},
		Filter: Filter{Rule: []Rule{{Type: "pass"}}},
		Dhcpd: Dhcpd{
			Items: map[string]DhcpdInterface{
				"lan": {Enable: "1"},
			},
		},
	}

	// Test SystemConfig helper
	systemConfig := opnsense.SystemConfig()
	assert.Equal(t, "test-hostname", systemConfig.System.Hostname)
	assert.Equal(t, "test.local", systemConfig.System.Domain)
	assert.Len(t, systemConfig.Sysctl, 1)
	assert.Equal(t, "net.inet.ip.test", systemConfig.Sysctl[0].Tunable)

	// Test NetworkConfig helper
	networkConfig := opnsense.NetworkConfig()
	wan, wanExists := networkConfig.Interfaces.Get("wan")
	assert.True(t, wanExists)
	assert.Equal(t, "em0", wan.If)
	lan, lanExists := networkConfig.Interfaces.Get("lan")
	assert.True(t, lanExists)
	assert.Equal(t, "em1", lan.If)

	// Test SecurityConfig helper
	securityConfig := opnsense.SecurityConfig()
	assert.Equal(t, "automatic", securityConfig.Nat.Outbound.Mode)
	assert.Len(t, securityConfig.Filter.Rule, 1)

	// Test ServiceConfig helper
	serviceConfig := opnsense.ServiceConfig()
	lanDhcp, lanDhcpExists := serviceConfig.Dhcpd.Get("lan")
	assert.True(t, lanDhcpExists)
	assert.Equal(t, "1", lanDhcp.Enable)
}

func TestOpnsenseModel_Validation(t *testing.T) {
	validate := validator.New()

	// Test valid configuration
	validConfig := Opnsense{
		System: System{
			Hostname: "test-host",
			Domain:   "test.local",
			Webgui:   Webgui{Protocol: "https"},
			SSH:      SSH{Group: "admins"},
		},
		Interfaces: Interfaces{
			Items: map[string]Interface{
				"wan": {If: "em0"},
				"lan": {If: "em1"},
			},
		},
		Sysctl: []SysctlItem{
			{Tunable: "net.inet.ip.test", Value: "1"},
		},
	}

	err := validate.Struct(validConfig)
	assert.NoError(t, err)

	// Test invalid configuration - missing required fields
	invalidConfig := Opnsense{
		Sysctl: []SysctlItem{
			{Tunable: "", Value: ""}, // Empty required fields
		},
	}

	err = validate.Struct(invalidConfig)
	assert.Error(t, err)
}

func TestSysctlItem_Validation(t *testing.T) {
	validate := validator.New()

	// Test valid SysctlItem
	validItem := SysctlItem{
		Tunable: "net.inet.ip.test",
		Value:   "1",
		Descr:   "Test description",
	}

	err := validate.Struct(validItem)
	assert.NoError(t, err)

	// Test invalid SysctlItem - missing required fields
	invalidItem := SysctlItem{
		Tunable: "", // Required field is empty
		Value:   "", // Required field is empty
		Descr:   "Description",
	}

	err = validate.Struct(invalidItem)
	assert.Error(t, err)
}

// TestOpnsenseModel_XMLUnmarshalFromFile tests XML unmarshalling from the sample testdata file.
func TestOpnsenseModel_XMLUnmarshalFromFile(t *testing.T) {
	// Read the sample XML file
	xmlPath := filepath.Join("..", "..", "testdata", "config.xml")
	xmlData, err := os.ReadFile(xmlPath)
	require.NoError(t, err, "Failed to read testdata XML file")

	// Unmarshal into struct
	var opnsense Opnsense
	err = xml.Unmarshal(xmlData, &opnsense)
	require.NoError(t, err, "XML unmarshalling should succeed")

	// Verify basic structure is correctly loaded
	assert.Equal(t, "24.1.1", opnsense.Version)
	assert.Equal(t, "opnsense", opnsense.Theme)
	assert.Equal(t, "TestHost", opnsense.System.Hostname)
	assert.Equal(t, "test.local", opnsense.System.Domain)

	// Verify complex nested structures
	assert.Len(t, opnsense.Sysctl, 2)
	assert.Equal(t, "net.inet.ip.random_id", opnsense.Sysctl[0].Tunable)
	assert.Equal(t, "1", opnsense.Sysctl[0].Value)

	// Verify system users and groups
	assert.Len(t, opnsense.System.User, 2)
	assert.Equal(t, "root", opnsense.System.User[0].Name)
	assert.Equal(t, "testuser", opnsense.System.User[1].Name)

	assert.Len(t, opnsense.System.Group, 2)
	assert.Equal(t, "admins", opnsense.System.Group[0].Name)
	assert.Equal(t, "users", opnsense.System.Group[1].Name)

	// Verify interfaces
	wan, wanExists := opnsense.Interfaces.Get("wan")
	assert.True(t, wanExists)
	assert.Equal(t, "em0", wan.If)
	assert.Equal(t, "dhcp", wan.IPAddr)
	lan, lanExists := opnsense.Interfaces.Get("lan")
	assert.True(t, lanExists)
	assert.Equal(t, "em1", lan.If)
	assert.Equal(t, "192.168.1.1", lan.IPAddr)

	// Verify filter rules
	assert.Len(t, opnsense.Filter.Rule, 3)
	assert.Equal(t, "pass", opnsense.Filter.Rule[0].Type)
	assert.Equal(t, "block", opnsense.Filter.Rule[2].Type)

	// Verify load balancer monitors
	assert.Len(t, opnsense.LoadBalancer.MonitorType, 2)
	assert.Equal(t, "ICMP", opnsense.LoadBalancer.MonitorType[0].Name)
	assert.Equal(t, "HTTP", opnsense.LoadBalancer.MonitorType[1].Name)
}

// TestOpnsenseModel_MissingRequiredFieldsValidation tests that validation catches missing required fields.
func TestOpnsenseModel_MissingRequiredFieldsValidation(t *testing.T) {
	validate := validator.New()

	tests := []struct {
		name    string
		config  Opnsense
		wantErr bool
	}{
		{
			name: "Missing hostname in system",
			config: Opnsense{
				System: System{
					Domain: "test.local",
					Webgui: Webgui{Protocol: "https"},
					SSH:    SSH{Group: "admins"},
				},
				Interfaces: Interfaces{
					Items: map[string]Interface{
						"wan": {If: "em0"},
						"lan": {If: "em1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Missing domain in system",
			config: Opnsense{
				System: System{
					Hostname: "test-host",
					Webgui:   Webgui{Protocol: "https"},
					SSH:      SSH{Group: "admins"},
				},
				Interfaces: Interfaces{
					Items: map[string]Interface{
						"wan": {If: "em0"},
						"lan": {If: "em1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Missing webgui protocol",
			config: Opnsense{
				System: System{
					Hostname: "test-host",
					Domain:   "test.local",
					SSH:      SSH{Group: "admins"},
				},
				Interfaces: Interfaces{
					Items: map[string]Interface{
						"wan": {If: "em0"},
						"lan": {If: "em1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Missing SSH group",
			config: Opnsense{
				System: System{
					Hostname: "test-host",
					Domain:   "test.local",
					Webgui:   Webgui{Protocol: "https"},
				},
				Interfaces: Interfaces{
					Items: map[string]Interface{
						"wan": {If: "em0"},
						"lan": {If: "em1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Missing sysctl tunable",
			config: Opnsense{
				System: System{
					Hostname: "test-host",
					Domain:   "test.local",
					Webgui:   Webgui{Protocol: "https"},
					SSH:      SSH{Group: "admins"},
				},
				Interfaces: Interfaces{
					Items: map[string]Interface{
						"wan": {If: "em0"},
						"lan": {If: "em1"},
					},
				},
				Sysctl: []SysctlItem{
					{Value: "1", Descr: "Test"}, // Missing Tunable
				},
			},
			wantErr: true,
		},
		{
			name: "Missing sysctl value",
			config: Opnsense{
				System: System{
					Hostname: "test-host",
					Domain:   "test.local",
					Webgui:   Webgui{Protocol: "https"},
					SSH:      SSH{Group: "admins"},
				},
				Interfaces: Interfaces{
					Items: map[string]Interface{
						"wan": {If: "em0"},
						"lan": {If: "em1"},
					},
				},
				Sysctl: []SysctlItem{
					{Tunable: "net.inet.ip.test", Descr: "Test"}, // Missing Value
				},
			},
			wantErr: true,
		},
		{
			name: "Valid complete configuration",
			config: Opnsense{
				System: System{
					Hostname: "test-host",
					Domain:   "test.local",
					Webgui:   Webgui{Protocol: "https"},
					SSH:      SSH{Group: "admins"},
				},
				Interfaces: Interfaces{
					Items: map[string]Interface{
						"wan": {If: "em0"},
						"lan": {If: "em1"},
					},
				},
				Sysctl: []SysctlItem{
					{Tunable: "net.inet.ip.test", Value: "1", Descr: "Test"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate.Struct(tt.config)
			if tt.wantErr {
				assert.Error(t, err, "Expected validation error for %s", tt.name)
			} else {
				assert.NoError(t, err, "Expected no validation error for %s", tt.name)
			}
		})
	}
}

// TestOpnsenseModel_XMLUnmarshalInvalid tests handling of invalid XML.
func TestOpnsenseModel_XMLUnmarshalInvalid(t *testing.T) {
	tests := []struct {
		name    string
		xmlData string
		wantErr bool
	}{
		{
			name:    "Invalid XML syntax",
			xmlData: `<opnsense><system><hostname>test</system></opnsense>`, // Missing closing hostname tag
			wantErr: true,
		},
		{
			name:    "Empty XML",
			xmlData: ``,
			wantErr: true,
		},
		{
			name:    "Valid minimal XML",
			xmlData: `<opnsense><system><hostname>test</hostname><domain>test.local</domain></system><interfaces><wan/><lan/></interfaces></opnsense>`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opnsense Opnsense
			err := xml.Unmarshal([]byte(tt.xmlData), &opnsense)
			if tt.wantErr {
				assert.Error(t, err, "Expected XML unmarshalling error for %s", tt.name)
			} else {
				assert.NoError(t, err, "Expected no XML unmarshalling error for %s", tt.name)
			}
		})
	}
}

// TestOpnsenseModel_EdgeCases tests edge cases in the model.
func TestOpnsenseModel_EdgeCases(t *testing.T) {
	t.Run("Empty opnsense struct", func(t *testing.T) {
		opnsense := Opnsense{}

		// Should not panic and return empty values
		assert.Equal(t, "", opnsense.Hostname())
		assert.Nil(t, opnsense.InterfaceByName("any"))
		assert.Len(t, opnsense.FilterRules(), 0)

		// Config helpers should return empty structs
		sysConfig := opnsense.SystemConfig()
		assert.Equal(t, "", sysConfig.System.Hostname)
		assert.Len(t, sysConfig.Sysctl, 0)

		netConfig := opnsense.NetworkConfig()
		_, wanExists := netConfig.Interfaces.Get("wan")
		assert.False(t, wanExists)

		secConfig := opnsense.SecurityConfig()
		assert.Equal(t, "", secConfig.Nat.Outbound.Mode)

		svcConfig := opnsense.ServiceConfig()
		_, lanDhcpExists := svcConfig.Dhcpd.Get("lan")
		assert.False(t, lanDhcpExists)
	})

	t.Run("Nil pointer safety", func(t *testing.T) {
		// Test that helper methods don't panic with partially initialized structs
		opnsense := Opnsense{
			System: System{Hostname: "test"},
			// Interfaces not initialized
		}

		assert.Equal(t, "test", opnsense.Hostname())
		assert.Nil(t, opnsense.InterfaceByName("em0"))
	})

	t.Run("InterfaceByName reflection-based search", func(t *testing.T) {
		// Test that InterfaceByName works with reflection-based field discovery
		opnsense := Opnsense{
			Interfaces: Interfaces{
				Items: map[string]Interface{
					"wan": {If: "em0", IPAddr: "dhcp"},
					"lan": {If: "em1", IPAddr: "192.168.1.1"},
				},
			},
		}

		// Test finding existing interfaces
		wanInterface := opnsense.InterfaceByName("em0")
		require.NotNil(t, wanInterface)
		assert.Equal(t, "em0", wanInterface.If)
		assert.Equal(t, "dhcp", wanInterface.IPAddr)

		lanInterface := opnsense.InterfaceByName("em1")
		require.NotNil(t, lanInterface)
		assert.Equal(t, "em1", lanInterface.If)
		assert.Equal(t, "192.168.1.1", lanInterface.IPAddr)

		// Test finding non-existent interface
		nonExistentInterface := opnsense.InterfaceByName("em2")
		assert.Nil(t, nonExistentInterface)

		// Test with empty interface names
		emptyInterface := opnsense.InterfaceByName("")
		assert.Nil(t, emptyInterface)
	})
}
