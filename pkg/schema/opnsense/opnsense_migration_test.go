package opnsense

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errUnsupportedCharset is returned when an unsupported charset is encountered.
var errUnsupportedCharset = errors.New("unsupported charset")

// testdataDir returns the path to the testdata directory relative to this package.
func testdataDir() string {
	return filepath.Join("..", "..", "..", "testdata")
}

// Tests migrated from internal/model/opnsense_test.go

func TestOpnSenseDocument_XMLUnmarshalling(t *testing.T) {
	t.Parallel()

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

	assert.Equal(t, "1.2.3", opnsense.Version)
	assert.Equal(t, "opnsense", opnsense.Theme)
	assert.Equal(t, "test-host", opnsense.System.Hostname)
	assert.Equal(t, "test.local", opnsense.System.Domain)

	wan, exists := opnsense.Interfaces.Items["wan"]
	assert.True(t, exists)
	assert.Equal(t, "em0", wan.If)
	assert.Equal(t, "dhcp", wan.IPAddr)

	lan, exists := opnsense.Interfaces.Items["lan"]
	assert.True(t, exists)
	assert.Equal(t, "em1", lan.If)
	assert.Equal(t, "192.168.1.1", lan.IPAddr)
	assert.Equal(t, "24", lan.Subnet)

	assert.Equal(t, "automatic", opnsense.Nat.Outbound.Mode)

	require.Len(t, opnsense.Filter.Rule, 1)
	rule := opnsense.Filter.Rule[0]
	assert.Equal(t, "pass", rule.Type)
	assert.Equal(t, "inet", rule.IPProtocol)
	assert.Equal(t, "Test rule", rule.Descr)
	assert.Equal(t, "lan", rule.Interface.String())
	assert.Equal(t, "lan", rule.Source.Network)

	require.Len(t, opnsense.Sysctl, 1)
	sysctl := opnsense.Sysctl[0]
	assert.Equal(t, "Test sysctl", sysctl.Descr)
	assert.Equal(t, "net.inet.ip.test", sysctl.Tunable)
	assert.Equal(t, "1", sysctl.Value)
}

func TestOpnSenseDocument_Validation(t *testing.T) {
	t.Parallel()

	validate := validator.New()

	validConfig := OpnSenseDocument{
		System: System{
			Hostname: "test-host",
			Domain:   "test.local",
			WebGUI:   WebGUIConfig{Protocol: "https"},
			SSH:      SSHConfig{Group: "admins"},
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
	require.NoError(t, err)

	invalidConfig := OpnSenseDocument{
		Sysctl: []SysctlItem{
			{Tunable: "", Value: ""},
		},
	}

	err = validate.Struct(invalidConfig)
	require.Error(t, err)
}

func TestSysctlItem_Validation(t *testing.T) {
	t.Parallel()

	validate := validator.New()

	validItem := SysctlItem{
		Tunable: "net.inet.ip.test",
		Value:   "1",
		Descr:   "Test description",
	}

	err := validate.Struct(validItem)
	require.NoError(t, err)

	invalidItem := SysctlItem{
		Tunable: "",
		Value:   "",
		Descr:   "Description",
	}

	err = validate.Struct(invalidItem)
	require.Error(t, err)
}

// TestOpnSenseDocument_XMLUnmarshalFromFile tests XML unmarshalling from a sample testdata file.
func TestOpnSenseDocument_XMLUnmarshalFromFile(t *testing.T) {
	t.Parallel()

	xmlPath := filepath.Join(testdataDir(), "sample.config.1.xml")
	xmlData, err := os.ReadFile(xmlPath)
	require.NoError(t, err, "Failed to read testdata XML file")

	var opnsense OpnSenseDocument

	err = xml.Unmarshal(xmlData, &opnsense)
	require.NoError(t, err, "XML unmarshalling should succeed")

	assert.Equal(t, "opnsense", opnsense.Theme)
	assert.Equal(t, "OPNsense", opnsense.System.Hostname)
	assert.Equal(t, "localdomain", opnsense.System.Domain)

	assert.Len(t, opnsense.System.User, 1)
	assert.Equal(t, "root", opnsense.System.User[0].Name)

	assert.Len(t, opnsense.System.Group, 1)
	assert.Equal(t, "admins", opnsense.System.Group[0].Name)

	wan, wanExists := opnsense.Interfaces.Get("wan")
	assert.True(t, wanExists)
	assert.Equal(t, "mismatch1", wan.If)
	assert.Equal(t, "dhcp", wan.IPAddr)

	lan, lanExists := opnsense.Interfaces.Get("lan")
	assert.True(t, lanExists)
	assert.Equal(t, "mismatch0", lan.If)
	assert.Equal(t, "192.168.1.1", lan.IPAddr)

	assert.NotEmpty(t, opnsense.Filter.Rule)
	assert.Equal(t, "pass", opnsense.Filter.Rule[0].Type)

	assert.NotEmpty(t, opnsense.LoadBalancer.MonitorType)
	assert.Equal(t, "ICMP", opnsense.LoadBalancer.MonitorType[0].Name)
}

// TestOpnSenseDocument_MissingRequiredFieldsValidation tests that validation catches missing required fields.
func TestOpnSenseDocument_MissingRequiredFieldsValidation(t *testing.T) {
	t.Parallel()

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
					WebGUI: WebGUIConfig{Protocol: "https"},
					SSH:    SSHConfig{Group: "admins"},
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
					WebGUI:   WebGUIConfig{Protocol: "https"},
					SSH:      SSHConfig{Group: "admins"},
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
					SSH:      SSHConfig{Group: "admins"},
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
					WebGUI:   WebGUIConfig{Protocol: "https"},
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
					WebGUI:   WebGUIConfig{Protocol: "https"},
					SSH:      SSHConfig{Group: "admins"},
				},
				Interfaces: Interfaces{
					Items: map[string]Interface{
						"wan": {If: "em0"},
						"lan": {If: "em1"},
					},
				},
				Sysctl: []SysctlItem{
					{Value: "1", Descr: "Test"},
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
					WebGUI:   WebGUIConfig{Protocol: "https"},
					SSH:      SSHConfig{Group: "admins"},
				},
				Interfaces: Interfaces{
					Items: map[string]Interface{
						"wan": {If: "em0"},
						"lan": {If: "em1"},
					},
				},
				Sysctl: []SysctlItem{
					{Tunable: "net.inet.ip.test", Descr: "Test"},
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
					WebGUI:   WebGUIConfig{Protocol: "https"},
					SSH:      SSHConfig{Group: "admins"},
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
			t.Parallel()

			err := validate.Struct(tt.config)
			if tt.wantErr {
				require.Error(t, err, "Expected validation error for %s", tt.name)
			} else {
				require.NoError(t, err, "Expected no validation error for %s", tt.name)
			}
		})
	}
}

// TestOpnSenseDocument_XMLUnmarshalInvalid tests handling of invalid XML.
func TestOpnSenseDocument_XMLUnmarshalInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		xmlData string
		wantErr bool
	}{
		{
			name:    "Invalid XML syntax",
			xmlData: `<opnsense><system><hostname>test</system></opnsense>`,
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
			t.Parallel()

			var opnsense OpnSenseDocument

			err := xml.Unmarshal([]byte(tt.xmlData), &opnsense)
			if tt.wantErr {
				require.Error(t, err, "Expected XML unmarshalling error for %s", tt.name)
			} else {
				require.NoError(t, err, "Expected no XML unmarshalling error for %s", tt.name)
			}
		})
	}
}

// TestOpnSenseDocument_EdgeCases tests edge cases in the model.
func TestOpnSenseDocument_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("Empty opnsense struct", func(t *testing.T) {
		t.Parallel()

		opnsense := OpnSenseDocument{}

		assert.Empty(t, opnsense.Hostname())
		assert.Nil(t, opnsense.InterfaceByName("any"))
		assert.Empty(t, opnsense.FilterRules())

		sysConfig := opnsense.SystemConfig()
		assert.Empty(t, sysConfig.System.Hostname)
		assert.Empty(t, sysConfig.Sysctl)

		netConfig := opnsense.NetworkConfig()
		_, wanExists := netConfig.Interfaces.Get("wan")
		assert.False(t, wanExists)

		secConfig := opnsense.SecurityConfig()
		assert.Empty(t, secConfig.Nat.Outbound.Mode)

		svcConfig := opnsense.ServiceConfig()
		_, lanDhcpExists := svcConfig.Dhcpd.Get("lan")
		assert.False(t, lanDhcpExists)
	})

	t.Run("Nil pointer safety", func(t *testing.T) {
		t.Parallel()

		opnsense := OpnSenseDocument{
			System: System{Hostname: "test"},
		}

		assert.Equal(t, "test", opnsense.Hostname())
		assert.Nil(t, opnsense.InterfaceByName("em0"))
	})

	t.Run("InterfaceByName reflection-based search", func(t *testing.T) {
		t.Parallel()

		opnsense := OpnSenseDocument{
			Interfaces: Interfaces{
				Items: map[string]Interface{
					"wan": {If: "em0", IPAddr: "dhcp"},
					"lan": {If: "em1", IPAddr: "192.168.1.1"},
				},
			},
		}

		wanInterface := opnsense.InterfaceByName("em0")
		require.NotNil(t, wanInterface)
		assert.Equal(t, "em0", wanInterface.If)
		assert.Equal(t, "dhcp", wanInterface.IPAddr)

		lanInterface := opnsense.InterfaceByName("em1")
		require.NotNil(t, lanInterface)
		assert.Equal(t, "em1", lanInterface.If)
		assert.Equal(t, "192.168.1.1", lanInterface.IPAddr)

		nonExistentInterface := opnsense.InterfaceByName("em2")
		assert.Nil(t, nonExistentInterface)

		emptyInterface := opnsense.InterfaceByName("")
		assert.Nil(t, emptyInterface)
	})
}

// TestOpnSenseDocument_XMLCoverage iterates over all XML test files to ensure they unmarshal.
func TestOpnSenseDocument_XMLCoverage(t *testing.T) {
	t.Parallel()

	testDir := testdataDir()

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
			t.Parallel()

			absFile, err := filepath.Abs(file)
			if err != nil {
				t.Fatalf("failed to get absolute path for %s: %v", file, err)
			}
			absTestDir, err := filepath.Abs(testDir)
			if err != nil {
				t.Fatalf("failed to get absolute path for testdir: %v", err)
			}
			if !strings.HasPrefix(absFile, absTestDir) {
				t.Fatalf("file path %s is outside testdata directory", file)
			}

			// deepcode ignore PT/test: This is a test, not a deployed application.
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("failed to read %s: %v", file, err)
			}

			decoder := xml.NewDecoder(bytes.NewReader(data))
			decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
				switch charset {
				case "us-ascii", "ascii":
					return input, nil
				default:
					return nil, fmt.Errorf("%w: %s", errUnsupportedCharset, charset)
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

// Tests migrated from internal/model/interface_list_test.go

// TestInterfaceList_MarshalXML tests XML marshalling of InterfaceList within a wrapper struct.
func TestInterfaceList_MarshalXML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    InterfaceList
		expected string
	}{
		{
			name:     "single interface",
			input:    InterfaceList{"lan"},
			expected: `<test><interface>lan</interface></test>`,
		},
		{
			name:     "multiple interfaces",
			input:    InterfaceList{"lan", "wan", "opt1"},
			expected: `<test><interface>lan</interface><interface>wan</interface><interface>opt1</interface></test>`,
		},
		{
			name:     "empty interface list",
			input:    InterfaceList{},
			expected: `<test></test>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			type TestStruct struct {
				XMLName   xml.Name      `xml:"test"`
				Interface InterfaceList `xml:"interface,omitempty"`
			}

			input := TestStruct{Interface: tt.input}
			result, err := xml.Marshal(input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

// TestRule_InterfaceList_Integration tests comma-separated interface parsing in an XML Rule.
func TestRule_InterfaceList_Integration(t *testing.T) {
	t.Parallel()

	xmlData := `
	<rule>
		<type>pass</type>
		<interface>opt1,opt2,lan</interface>
		<ipprotocol>inet</ipprotocol>
		<source>
			<network>any</network>
		</source>
		<destination>
			<network>any</network>
		</destination>
		<descr>Test rule with comma-separated interfaces</descr>
	</rule>`

	var rule Rule
	err := xml.Unmarshal([]byte(xmlData), &rule)
	require.NoError(t, err)

	assert.Equal(t, "pass", rule.Type)
	assert.Equal(t, InterfaceList{"opt1", "opt2", "lan"}, rule.Interface)
	assert.Equal(t, "inet", rule.IPProtocol)
	assert.Equal(t, "Test rule with comma-separated interfaces", rule.Descr)

	assert.True(t, rule.Interface.Contains("opt1"))
	assert.True(t, rule.Interface.Contains("opt2"))
	assert.True(t, rule.Interface.Contains("lan"))
	assert.False(t, rule.Interface.Contains("wan"))

	assert.Equal(t, "opt1,opt2,lan", rule.Interface.String())
}
