package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unclesp1d3r/opnFocus/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXMLParser_Parse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *model.Opnsense
		wantErr  bool
	}{
		{
			name:  "valid config",
			input: `<opnsense><version>1.2.3</version><system><hostname>test-host</hostname><domain>test.local</domain></system></opnsense>`,
			expected: &model.Opnsense{
				Version: "1.2.3",
				System: model.System{
					Hostname: "test-host",
					Domain:   "test.local",
				},
			},
			wantErr: false,
		},
		{
			name:     "invalid xml",
			input:    `<opnsense><version>1.2.3</version><system><hostname>test-host</hostname></system>`,
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "empty input",
			input:    ` `,
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewXMLParser()
			opnsense, err := p.Parse(strings.NewReader(tt.input))

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, opnsense)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected.Version, opnsense.Version)
				assert.Equal(t, tt.expected.System.Hostname, opnsense.System.Hostname)
				assert.Equal(t, tt.expected.System.Domain, opnsense.System.Domain)
			}
		})
	}
}

// TestXMLParser_ParseSampleFiles tests parsing of real config.xml sample files.
func TestXMLParser_ParseSampleFiles(t *testing.T) {
	testDataDir := "testdata"

	// Get all .xml.sample files in testdata directory
	sampleFiles, err := filepath.Glob(filepath.Join(testDataDir, "*.xml.sample"))
	require.NoError(t, err, "Failed to find sample XML files")

	if len(sampleFiles) == 0 {
		t.Skip("No sample XML files found in testdata directory")
	}

	parser := NewXMLParser()

	for _, sampleFile := range sampleFiles {
		t.Run(filepath.Base(sampleFile), func(t *testing.T) {
			// Open and parse the file
			file, err := os.Open(sampleFile)
			require.NoError(t, err, "Failed to open sample file: %s", sampleFile)

			defer func() { _ = file.Close() }() //nolint:errcheck // Defer close

			opnsense, err := parser.Parse(file)
			require.NoError(t, err, "Failed to parse sample file: %s", sampleFile)
			require.NotNil(t, opnsense, "Parsed config should not be nil")

			// Run comprehensive validation
			validateOPNsenseConfig(t, opnsense, sampleFile)
		})
	}
}

// TestXMLParser_ParseConfigSample specifically tests the main config.xml.sample file.
func TestXMLParser_ParseConfigSample(t *testing.T) {
	sampleFile := filepath.Join("testdata", "config.xml.sample")

	// Check if file exists
	if _, err := os.Stat(sampleFile); os.IsNotExist(err) {
		t.Skip("config.xml.sample not found in testdata directory")
	}

	parser := NewXMLParser()
	file, err := os.Open(sampleFile)
	require.NoError(t, err)

	defer func() { _ = file.Close() }() //nolint:errcheck // Ignore error in test cleanup

	opnsense, err := parser.Parse(file)
	require.NoError(t, err)
	require.NotNil(t, opnsense)

	// Test specific expected values from config.xml.sample
	t.Run("System Configuration", func(t *testing.T) {
		assert.Equal(t, "opnsense", opnsense.Theme)
		assert.Equal(t, "OPNsense", opnsense.System.Hostname)
		assert.Equal(t, "localdomain", opnsense.System.Domain)
		assert.Equal(t, "normal", opnsense.System.Optimization)
		assert.Equal(t, "Etc/UTC", opnsense.System.Timezone)
		assert.Equal(t, "1", opnsense.System.DNSAllowOverride)
		assert.Equal(t, "https", opnsense.System.Webgui.Protocol)
	})

	t.Run("Users and Groups", func(t *testing.T) {
		require.Len(t, opnsense.System.Group, 1)
		assert.Equal(t, "admins", opnsense.System.Group[0].Name)
		assert.Equal(t, "System Administrators", opnsense.System.Group[0].Description)
		assert.Equal(t, "1999", opnsense.System.Group[0].Gid)

		require.Len(t, opnsense.System.User, 1)
		assert.Equal(t, "root", opnsense.System.User[0].Name)
		assert.Equal(t, "System Administrator", opnsense.System.User[0].Descr)
		assert.Equal(t, "admins", opnsense.System.User[0].Groupname)
		assert.Equal(t, "0", opnsense.System.User[0].UID)
	})

	t.Run("Network Interfaces", func(t *testing.T) {
		// WAN Interface
		assert.Equal(t, "1", opnsense.Interfaces.Wan.Enable)
		assert.Equal(t, "mismatch1", opnsense.Interfaces.Wan.If)
		assert.Equal(t, "dhcp", opnsense.Interfaces.Wan.IPAddr)
		assert.Equal(t, "dhcp6", opnsense.Interfaces.Wan.IPAddrv6)
		assert.Equal(t, "1", opnsense.Interfaces.Wan.BlockPriv)
		assert.Equal(t, "1", opnsense.Interfaces.Wan.BlockBogons)

		// LAN Interface
		assert.Equal(t, "1", opnsense.Interfaces.Lan.Enable)
		assert.Equal(t, "mismatch0", opnsense.Interfaces.Lan.If)
		assert.Equal(t, "192.168.1.1", opnsense.Interfaces.Lan.IPAddr)
		assert.Equal(t, "track6", opnsense.Interfaces.Lan.IPAddrv6)
		assert.Equal(t, "24", opnsense.Interfaces.Lan.Subnet)
		assert.Equal(t, "64", opnsense.Interfaces.Lan.Subnetv6)
		assert.Equal(t, "wan", opnsense.Interfaces.Lan.Track6Interface)
		assert.Equal(t, "0", opnsense.Interfaces.Lan.Track6PrefixID)
	})

	t.Run("DHCP Configuration", func(t *testing.T) {
		assert.Equal(t, "192.168.1.100", opnsense.Dhcpd.Lan.Range.From)
		assert.Equal(t, "192.168.1.199", opnsense.Dhcpd.Lan.Range.To)
	})

	t.Run("Services", func(t *testing.T) {
		assert.Equal(t, "1", opnsense.Unbound.Enable)
		assert.Equal(t, "public", opnsense.Snmpd.ROCommunity)
		assert.Equal(t, "automatic", opnsense.Nat.Outbound.Mode)
		assert.Equal(t, "0.opnsense.pool.ntp.org", opnsense.Ntpd.Prefer)
	})

	t.Run("Sysctl Items", func(t *testing.T) {
		assert.Greater(t, len(opnsense.Sysctl), 30, "Should have more than 30 sysctl items")

		// Check a specific sysctl item
		found := false

		for _, item := range opnsense.Sysctl {
			if item.Tunable == "net.inet.icmp.drop_redirect" {
				assert.Equal(t, "1", item.Value)

				found = true

				break
			}
		}

		assert.True(t, found, "Should find net.inet.icmp.drop_redirect sysctl item")
	})

	t.Run("Firewall Rules", func(t *testing.T) {
		assert.Len(t, opnsense.Filter.Rule, 2)

		// Check first rule
		assert.Equal(t, "pass", opnsense.Filter.Rule[0].Type)
		assert.Equal(t, "inet", opnsense.Filter.Rule[0].IPProtocol)
		assert.Equal(t, "Default allow LAN to any rule", opnsense.Filter.Rule[0].Descr)
		assert.Equal(t, "lan", opnsense.Filter.Rule[0].Interface)
		assert.Equal(t, "lan", opnsense.Filter.Rule[0].Source.Network)

		// Check second rule (IPv6)
		assert.Equal(t, "pass", opnsense.Filter.Rule[1].Type)
		assert.Equal(t, "inet6", opnsense.Filter.Rule[1].IPProtocol)
		assert.Equal(t, "Default allow LAN IPv6 to any rule", opnsense.Filter.Rule[1].Descr)
	})

	t.Run("Load Balancer", func(t *testing.T) {
		assert.Len(t, opnsense.LoadBalancer.MonitorType, 5)

		// Check monitor types
		monitorNames := make([]string, len(opnsense.LoadBalancer.MonitorType))
		for i, monitor := range opnsense.LoadBalancer.MonitorType {
			monitorNames[i] = monitor.Name
		}

		assert.Contains(t, monitorNames, "ICMP")
		assert.Contains(t, monitorNames, "TCP")
		assert.Contains(t, monitorNames, "HTTP")
		assert.Contains(t, monitorNames, "HTTPS")
		assert.Contains(t, monitorNames, "SMTP")
	})

	t.Run("Widgets", func(t *testing.T) {
		assert.Equal(t, "2", opnsense.Widgets.ColumnCount)
		assert.Contains(t, opnsense.Widgets.Sequence, "system_information-container")
	})
}

// validateOPNsenseConfig performs comprehensive validation of an OPNsense configuration.
func validateOPNsenseConfig(t *testing.T, config *model.Opnsense, _ string) {
	t.Helper()

	t.Run("Basic Structure", func(t *testing.T) {
		assert.NotNil(t, config, "Config should not be nil")
		assert.Equal(t, "opnsense", config.XMLName.Local, "Root element should be 'opnsense'")
	})

	t.Run("System Configuration", func(t *testing.T) {
		assert.NotEmpty(t, config.System.Hostname, "Hostname should not be empty")
		assert.NotEmpty(t, config.System.Domain, "Domain should not be empty")

		// Validate users if present
		for i, user := range config.System.User {
			assert.NotEmpty(t, user.Name, "User %d name should not be empty", i)
			assert.NotEmpty(t, user.UID, "User %d UID should not be empty", i)
		}

		// Validate groups if present
		for i, group := range config.System.Group {
			assert.NotEmpty(t, group.Name, "Group %d name should not be empty", i)
			assert.NotEmpty(t, group.Gid, "Group %d GID should not be empty", i)
		}
	})

	t.Run("Network Interfaces", func(t *testing.T) {
		// At least one interface should be enabled
		wanEnabled := config.Interfaces.Wan.Enable == "1"
		lanEnabled := config.Interfaces.Lan.Enable == "1"
		assert.True(t, wanEnabled || lanEnabled, "At least one interface should be enabled")

		// Validate interface names if specified
		if config.Interfaces.Wan.If != "" {
			assert.NotEmpty(t, config.Interfaces.Wan.If, "WAN interface name should not be empty if specified")
		}

		if config.Interfaces.Lan.If != "" {
			assert.NotEmpty(t, config.Interfaces.Lan.If, "LAN interface name should not be empty if specified")
		}
	})

	t.Run("Sysctl Items", func(t *testing.T) {
		for i, item := range config.Sysctl {
			assert.NotEmpty(t, item.Tunable, "Sysctl item %d tunable should not be empty", i)
			assert.NotEmpty(t, item.Value, "Sysctl item %d value should not be empty", i)
			// Description can be empty, but if present should be reasonable
			if item.Descr != "" {
				assert.Greater(t, len(item.Descr), 5, "Sysctl item %d description should be meaningful", i)
			}
		}
	})

	t.Run("Firewall Rules", func(t *testing.T) {
		for i, rule := range config.Filter.Rule {
			assert.NotEmpty(t, rule.Type, "Rule %d type should not be empty", i)
			assert.Contains(t, []string{"pass", "block", "reject"}, rule.Type, "Rule %d type should be valid", i)

			if rule.IPProtocol != "" {
				assert.Contains(t, []string{"inet", "inet6"}, rule.IPProtocol, "Rule %d IP protocol should be valid", i)
			}

			if rule.Interface != "" {
				assert.NotEmpty(t, rule.Interface, "Rule %d interface should not be empty if specified", i)
			}
		}
	})

	t.Run("Load Balancer Monitors", func(t *testing.T) {
		for i, monitor := range config.LoadBalancer.MonitorType {
			assert.NotEmpty(t, monitor.Name, "Monitor %d name should not be empty", i)
			assert.NotEmpty(t, monitor.Type, "Monitor %d type should not be empty", i)

			// Validate common monitor types
			validTypes := []string{"icmp", "tcp", "http", "https", "send"}
			assert.Contains(t, validTypes, monitor.Type, "Monitor %d type should be valid", i)
		}
	})
}

// BenchmarkXMLParser_Parse benchmarks the parsing performance.
func BenchmarkXMLParser_Parse(b *testing.B) {
	sampleFile := filepath.Join("testdata", "config.xml.sample")

	// Check if file exists
	if _, err := os.Stat(sampleFile); os.IsNotExist(err) {
		b.Skip("config.xml.sample not found in testdata directory")
	}

	parser := NewXMLParser()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		file, err := os.Open(sampleFile)
		if err != nil {
			b.Fatal(err)
		}

		_, err = parser.Parse(file)
		if err != nil {
			_ = file.Close() //nolint:errcheck // Ignore error in benchmark cleanup

			b.Fatal(err)
		}

		_ = file.Close() //nolint:errcheck // Ignore error in benchmark cleanup
	}
}
