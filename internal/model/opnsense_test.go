package model

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ErrUnsupportedCharset is returned when an unsupported charset is encountered.
var ErrUnsupportedCharset = errors.New("unsupported charset")

func TestOpnSenseDocumentModel_XMLUnmarshalling(t *testing.T) {
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

	var opnsense OpnSenseDocument
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

func TestOpnSenseDocumentModel_HelperMethods(t *testing.T) {
	opnsense := OpnSenseDocument{
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

func TestOpnSenseDocumentModel_ConfigGroupHelpers(t *testing.T) {
	opnsense := OpnSenseDocument{
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

func TestOpnSenseDocumentModel_Validation(t *testing.T) {
	validate := validator.New()

	// Test valid configuration
	validConfig := OpnSenseDocument{
		System: System{
			Hostname: "test-host",
			Domain:   "test.local",
			WebGUI: struct {
				Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
				SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
			}{Protocol: "https"},
			SSH: struct {
				Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
			}{Group: "admins"},
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
	invalidConfig := OpnSenseDocument{
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

// TestOpnSenseDocumentModel_XMLUnmarshalFromFile tests XML unmarshalling from the sample testdata file.
func TestOpnSenseDocumentModel_XMLUnmarshalFromFile(t *testing.T) {
	// Read the sample XML file
	xmlPath := filepath.Join("..", "..", "testdata", "sample.config.1.xml")
	xmlData, err := os.ReadFile(xmlPath)
	require.NoError(t, err, "Failed to read testdata XML file")

	// Unmarshal into struct
	var opnsense OpnSenseDocument
	err = xml.Unmarshal(xmlData, &opnsense)
	require.NoError(t, err, "XML unmarshalling should succeed")

	// Verify basic structure is correctly loaded
	assert.Equal(t, "opnsense", opnsense.Theme)
	assert.Equal(t, "OPNsense", opnsense.System.Hostname)
	assert.Equal(t, "localdomain", opnsense.System.Domain)

	// Note: sysctl parsing is tested in parser tests, not here
	// This test focuses on model structure validation

	// Verify system users and groups
	assert.Len(t, opnsense.System.User, 1)
	assert.Equal(t, "root", opnsense.System.User[0].Name)

	assert.Len(t, opnsense.System.Group, 1)
	assert.Equal(t, "admins", opnsense.System.Group[0].Name)

	// Verify interfaces
	wan, wanExists := opnsense.Interfaces.Get("wan")
	assert.True(t, wanExists)
	assert.Equal(t, "mismatch1", wan.If)
	assert.Equal(t, "dhcp", wan.IPAddr)
	lan, lanExists := opnsense.Interfaces.Get("lan")
	assert.True(t, lanExists)
	assert.Equal(t, "mismatch0", lan.If)
	assert.Equal(t, "192.168.1.1", lan.IPAddr)

	// Verify filter rules
	assert.Greater(t, len(opnsense.Filter.Rule), 0)
	assert.Equal(t, "pass", opnsense.Filter.Rule[0].Type)

	// Verify load balancer monitors
	assert.Greater(t, len(opnsense.LoadBalancer.MonitorType), 0)
	assert.Equal(t, "ICMP", opnsense.LoadBalancer.MonitorType[0].Name)
}

// TestOpnSenseDocumentModel_MissingRequiredFieldsValidation tests that validation catches missing required fields.
func TestOpnSenseDocumentModel_MissingRequiredFieldsValidation(t *testing.T) {
	validate := validator.New()

	tests := []struct {
		name    string
		config  OpnSenseDocument
		wantErr bool
	}{
		{
			name: "Missing hostname in system",
			config: OpnSenseDocument{
				System: System{
					Domain: "test.local",
					WebGUI: struct {
						Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
						SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
					}{Protocol: "https"},
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{Group: "admins"},
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
			config: OpnSenseDocument{
				System: System{
					Hostname: "test-host",
					WebGUI: struct {
						Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
						SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
					}{Protocol: "https"},
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{Group: "admins"},
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
			config: OpnSenseDocument{
				System: System{
					Hostname: "test-host",
					Domain:   "test.local",
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{Group: "admins"},
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
			config: OpnSenseDocument{
				System: System{
					Hostname: "test-host",
					Domain:   "test.local",
					WebGUI: struct {
						Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
						SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
					}{Protocol: "https"},
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
			config: OpnSenseDocument{
				System: System{
					Hostname: "test-host",
					Domain:   "test.local",
					WebGUI: struct {
						Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
						SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
					}{Protocol: "https"},
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{Group: "admins"},
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
			config: OpnSenseDocument{
				System: System{
					Hostname: "test-host",
					Domain:   "test.local",
					WebGUI: struct {
						Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
						SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
					}{Protocol: "https"},
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{Group: "admins"},
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
			config: OpnSenseDocument{
				System: System{
					Hostname: "test-host",
					Domain:   "test.local",
					WebGUI: struct {
						Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
						SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
					}{Protocol: "https"},
					SSH: struct {
						Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
					}{Group: "admins"},
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

// TestOpnSenseDocumentModel_XMLUnmarshalInvalid tests handling of invalid XML.
func TestOpnSenseDocumentModel_XMLUnmarshalInvalid(t *testing.T) {
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
			var opnsense OpnSenseDocument
			err := xml.Unmarshal([]byte(tt.xmlData), &opnsense)
			if tt.wantErr {
				assert.Error(t, err, "Expected XML unmarshalling error for %s", tt.name)
			} else {
				assert.NoError(t, err, "Expected no XML unmarshalling error for %s", tt.name)
			}
		})
	}
}

// TestOpnSenseDocumentModel_EdgeCases tests edge cases in the model.
func TestOpnSenseDocumentModel_EdgeCases(t *testing.T) {
	t.Run("Empty opnsense struct", func(t *testing.T) {
		opnsense := OpnSenseDocument{}

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
		opnsense := OpnSenseDocument{
			System: System{Hostname: "test"},
			// Interfaces not initialized
		}

		assert.Equal(t, "test", opnsense.Hostname())
		assert.Nil(t, opnsense.InterfaceByName("em0"))
	})

	t.Run("InterfaceByName reflection-based search", func(t *testing.T) {
		// Test that InterfaceByName works with reflection-based field discovery
		opnsense := OpnSenseDocument{
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

func TestOpnSenseDocumentModel_XMLCoverage(t *testing.T) {
	testDir := "../../testdata"
	files, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("failed to read testdata directory: %v", err)
	}

	var xmlFiles []string
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".xml" {
			xmlFiles = append(xmlFiles, filepath.Join(testDir, f.Name()))
		}
	}

	if len(xmlFiles) == 0 {
		t.Fatalf("no XML files found in testdata directory")
	}

	for _, file := range xmlFiles {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("failed to read %s: %v", file, err)
			}

			// Create a decoder with custom charset reader to handle us-ascii encoding
			decoder := xml.NewDecoder(bytes.NewReader(data))
			decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
				switch charset {
				case "us-ascii", "ascii":
					// us-ascii is a subset of UTF-8, so we can just return the input
					return input, nil
				default:
					// For other charsets, return an error to maintain strict behavior
					return nil, fmt.Errorf("%w: %s", ErrUnsupportedCharset, charset)
				}
			}

			var config OpnSenseDocument
			err = decoder.Decode(&config)
			if err != nil {
				t.Errorf("failed to unmarshal %s: %v", file, err)
			}
		})
	}
}
