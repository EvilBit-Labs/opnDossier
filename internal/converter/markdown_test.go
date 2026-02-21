package converter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarkdownConverter_ToMarkdown(t *testing.T) {
	// Set terminal to dumb for consistent test output
	t.Setenv("TERM", "dumb")

	tests := []struct {
		name     string
		input    *common.CommonDevice
		expected string
		wantErr  bool
	}{
		{
			name: "basic conversion",
			input: &common.CommonDevice{
				Version: "1.2.3",
				System: common.System{
					Hostname: "test-host",
					Domain:   "test.local",
				},
			},
			expected: `OPNsense Configuration

  ## System

  Hostname: test-host Domain: test.local`,
			wantErr: false,
		},
		{
			name:     "nil input",
			input:    nil,
			expected: "",
			wantErr:  true,
		},
		{
			name:     "empty struct",
			input:    &common.CommonDevice{},
			expected: "OPNsense Configuration",
			wantErr:  false,
		},
		{
			name: "missing system fields",
			input: &common.CommonDevice{
				System: common.System{},
			},
			expected: "OPNsense Configuration",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TERM is already set to "dumb" at the top of the test function

			c := NewMarkdownConverter()
			md, err := c.ToMarkdown(context.Background(), tt.input)

			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, md)
			} else {
				require.NoError(t, err)

				// With TERM=dumb, we get clean output without ANSI codes
				assert.Contains(t, md, "OPNsense Configuration")
				assert.Contains(t, md, "## System")

				if tt.input != nil && tt.input.System.Hostname != "" && tt.input.System.Domain != "" {
					// Check for hostname and domain separately to be more flexible
					assert.Contains(t, md, "**Hostname**: "+tt.input.System.Hostname)
					assert.Contains(t, md, "**Domain**: "+tt.input.System.Domain)
				}
			}
		})
	}
}

// TestMarkdownConverter_ConvertFromTestdataFile tests conversion of the complete testdata file.
func TestMarkdownConverter_ConvertFromTestdataFile(t *testing.T) {
	// Set terminal to dumb for consistent test output
	t.Setenv("TERM", "dumb")
	// Read the sample XML file
	xmlPath := filepath.Join("..", "..", "testdata", "sample.config.3.xml")
	xmlData, err := os.ReadFile(xmlPath)
	require.NoError(t, err, "Failed to read testdata XML file")

	// Parse the XML file and convert to CommonDevice
	factory := model.NewParserFactory()
	device, err := factory.CreateDevice(context.Background(), strings.NewReader(string(xmlData)), "", false)
	require.NoError(t, err, "XML parsing should succeed")

	// Convert to markdown
	c := NewMarkdownConverter()
	markdown, err := c.ToMarkdown(context.Background(), device)
	require.NoError(t, err, "Markdown conversion should succeed")

	// Verify the markdown is not empty
	assert.NotEmpty(t, markdown, "Markdown output should not be empty")

	// With TERM=dumb, we get clean output without ANSI codes
	// Verify main sections are present
	assert.Contains(t, markdown, "OPNsense Configuration")
	assert.Contains(t, markdown, "## System Configuration")
	assert.Contains(t, markdown, "## Network Configuration")
	assert.Contains(t, markdown, "## Security Configuration")
	assert.Contains(t, markdown, "## Service Configuration")

	// Verify system information
	assert.Contains(t, markdown, "**Hostname**: OPNsense")
	assert.Contains(t, markdown, "**Domain**: localdomain")
	assert.Contains(t, markdown, "**Optimization**:")
	assert.Contains(t, markdown, "normal")
	assert.Contains(t, markdown, "**Protocol**: https")

	// Verify network interfaces (title-cased from Name field)
	assert.Contains(t, markdown, "Wan Interface")
	assert.Contains(t, markdown, "Lan Interface")
	assert.Contains(t, markdown, "**Physical Interface**: mismatch1")
	assert.Contains(t, markdown, "**Physical Interface**: mismatch0")
	assert.Contains(t, markdown, "**IPv4 Address**: dhcp")
	assert.Contains(t, markdown, "192.168.1.1")

	// Verify security configuration
	assert.Contains(t, markdown, "NAT Configuration")
	assert.Contains(t, markdown, "**Outbound NAT Mode**: automatic")
	assert.Contains(t, markdown, "Firewall Rules")

	// Verify service configuration
	assert.Contains(t, markdown, "DHCP Server")
	assert.Contains(t, markdown, "DNS Resolver (Unbound)")
	assert.Contains(t, markdown, "SNMP")
	assert.Contains(t, markdown, "**Read-Only Community**: public")

	// Verify tables are rendered (headers are title case after markdown library v0.10.0)
	assert.Contains(t, markdown, "Tunable")
	assert.Contains(t, markdown, "Value")
	assert.Contains(t, markdown, "Description")

	// Verify users and groups tables
	assert.Contains(t, markdown, "Users")
	assert.Contains(t, markdown, "Groups")
	assert.Contains(t, markdown, "root")
	assert.Contains(t, markdown, "admins")

	// Verify firewall rules table (may be truncated due to width, headers are title case after markdown library v0.10.0)
	assert.Contains(t, markdown, "Type")
	assert.Contains(t, markdown, "Inter") // May be truncated from "Interface"
	assert.Contains(t, markdown, "IP")    // May be truncated from "IP Ver"
	assert.Contains(t, markdown, "Protocol")
	assert.Contains(t, markdown, "Sou") // May be truncated from "Source"
	assert.Contains(t, markdown, "Des") // May be truncated from "Destination"
	// Verify that the actual data shows both IP version and protocol
	assert.Contains(t, markdown, "inet")  // IPProtocol data
	assert.Contains(t, markdown, "inet6") // IPProtocol data

	// Verify load balancer monitors
	assert.Contains(t, markdown, "Load Balancer Monitors")
	assert.Contains(t, markdown, "ICMP")
	assert.Contains(t, markdown, "HTTP")
}

// TestMarkdownConverter_EdgeCases tests edge cases and error conditions.
func TestMarkdownConverter_EdgeCases(t *testing.T) {
	// Set terminal to dumb for consistent test output
	t.Setenv("TERM", "dumb")

	c := NewMarkdownConverter()

	t.Run("nil opnsense struct", func(t *testing.T) {
		md, err := c.ToMarkdown(context.Background(), nil)
		require.Error(t, err)
		assert.Equal(t, ErrNilDevice, err)
		assert.Empty(t, md)
	})

	t.Run("empty opnsense struct", func(t *testing.T) {
		md, err := c.ToMarkdown(context.Background(), &common.CommonDevice{})
		require.NoError(t, err)
		assert.NotEmpty(t, md)
		assert.Contains(t, md, "OPNsense Configuration")
	})

	t.Run("opnsense with only system configuration", func(t *testing.T) {
		device := &common.CommonDevice{
			System: common.System{
				Hostname: "test-host",
				Domain:   "test.local",
				WebGUI:   common.WebGUI{Protocol: "http"},
				Bogons:   common.Bogons{Interval: "monthly"},
			},
		}
		md, err := c.ToMarkdown(context.Background(), device)
		require.NoError(t, err)
		assert.NotEmpty(t, md)

		assert.Contains(t, md, "**Hostname**: test-host")
		assert.Contains(t, md, "**Domain**: test.local")
		assert.Contains(t, md, "**Protocol**: http")
	})

	t.Run("opnsense with complex sysctl configuration", func(t *testing.T) {
		device := &common.CommonDevice{
			System: common.System{
				Hostname: "sysctl-test",
				Domain:   "test.local",
			},
			Sysctl: []common.SysctlItem{
				{
					Tunable:     "net.inet.ip.forwarding",
					Value:       "1",
					Description: "Enable IP forwarding",
				},
				{
					Tunable:     "kern.ipc.somaxconn",
					Value:       "1024",
					Description: "Maximum socket connections",
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), device)
		require.NoError(t, err)
		assert.NotEmpty(t, md)

		assert.Contains(t, md, "System Tuning")
		assert.Contains(t, md, "net.inet.ip.forwarding")
		assert.Contains(t, md, "kern.ipc.somaxconn")
		assert.Contains(t, md, "Enable IP forwarding")
		assert.Contains(t, md, "Maximum socket connections")
	})

	t.Run("opnsense with users and groups", func(t *testing.T) {
		device := &common.CommonDevice{
			System: common.System{
				Hostname: "user-test",
				Domain:   "test.local",
			},
			Users: []common.User{
				{
					Name:        "admin",
					Description: "Administrator",
					GroupName:   "wheel",
					Scope:       "system",
				},
			},
			Groups: []common.Group{
				{
					Name:        "wheel",
					Description: "Wheel Group",
					Scope:       "system",
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), device)
		require.NoError(t, err)
		assert.NotEmpty(t, md)

		assert.Contains(t, md, "Users")
		assert.Contains(t, md, "Groups")
		assert.Contains(t, md, "admin")
		assert.Contains(t, md, "wheel")
		assert.Contains(t, md, "Administrator")
		assert.Contains(t, md, "Wheel Group")
	})

	t.Run("opnsense with multiple firewall rules", func(t *testing.T) {
		device := &common.CommonDevice{
			System: common.System{
				Hostname: "firewall-test",
				Domain:   "test.local",
			},
			FirewallRules: []common.FirewallRule{
				{
					Type:        "pass",
					Interfaces:  []string{"lan"},
					IPProtocol:  "inet",
					Description: "Allow LAN",
					Source:      common.RuleEndpoint{Address: "lan"},
				},
				{
					Type:        "block",
					Interfaces:  []string{"wan"},
					IPProtocol:  "inet",
					Description: "Block external",
					Source:      common.RuleEndpoint{Address: "any"},
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), device)
		require.NoError(t, err)
		assert.NotEmpty(t, md)

		assert.Contains(t, md, "Firewall Rules")
		assert.Contains(t, md, "Allow LAN")
		assert.Contains(t, md, "Block extern")
		assert.Contains(t, md, "pass")
		assert.Contains(t, md, "block")
	})

	t.Run("firewall rules with actual protocol data", func(t *testing.T) {
		device := &common.CommonDevice{
			System: common.System{
				Hostname: "protocol-test",
				Domain:   "test.local",
			},
			FirewallRules: []common.FirewallRule{
				{
					Type:        "pass",
					Interfaces:  []string{"lan"},
					IPProtocol:  "inet",
					Protocol:    "tcp",
					Description: "Allow TCP",
					Source:      common.RuleEndpoint{Address: "lan"},
					Destination: common.RuleEndpoint{Port: "80"},
				},
				{
					Type:        "pass",
					Interfaces:  []string{"lan"},
					IPProtocol:  "inet",
					Protocol:    "udp",
					Description: "Allow UDP",
					Source:      common.RuleEndpoint{Address: "lan"},
					Destination: common.RuleEndpoint{Port: "53"},
				},
				{
					Type:        "pass",
					Interfaces:  []string{"wan"},
					IPProtocol:  "inet",
					Protocol:    "tcp/udp",
					Description: "Allow compound protocol",
					Source:      common.RuleEndpoint{Address: "any"},
					Destination: common.RuleEndpoint{Port: "443"},
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), device)
		require.NoError(t, err)
		assert.NotEmpty(t, md)

		assert.Contains(t, md, "Firewall Rules")
		// Verify the fix - protocol information should now be displayed
		assert.Contains(t, md, "tcp")
		assert.Contains(t, md, "udp")
		assert.Contains(t, md, "tcp/udp")
		assert.Contains(t, md, "Allow TCP")
		assert.Contains(t, md, "Allow UDP")
		// Check for the actual display which may be split across lines due to table formatting
		assert.Contains(t, md, "Allow compound")
	})

	t.Run("opnsense with load balancer monitors", func(t *testing.T) {
		device := &common.CommonDevice{
			System: common.System{
				Hostname: "lb-test",
				Domain:   "test.local",
			},
			LoadBalancer: common.LoadBalancerConfig{
				MonitorTypes: []common.MonitorType{
					{
						Name:        "TCP-80",
						Type:        "tcp",
						Description: "TCP port 80 check",
					},
					{
						Name:        "HTTPS-443",
						Type:        "https",
						Description: "HTTPS health check",
					},
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), device)
		require.NoError(t, err)
		assert.NotEmpty(t, md)

		assert.Contains(t, md, "Load Balancer Monitors")
		assert.Contains(t, md, "TCP-80")
		assert.Contains(t, md, "HTTPS-443")
		assert.Contains(t, md, "TCP port 80 check")
		assert.Contains(t, md, "HTTPS health check")
	})
}

// TestMarkdownConverter_ThemeSelection tests theme selection logic.
func TestMarkdownConverter_ThemeSelection(t *testing.T) {
	// Set terminal to dumb for consistent test output
	t.Setenv("TERM", "dumb")

	c := NewMarkdownConverter()

	t.Run("default theme selection", func(t *testing.T) {
		// Test the getTheme method indirectly through ToMarkdown
		device := &common.CommonDevice{
			System: common.System{
				Hostname: "theme-test",
				Domain:   "test.local",
			},
		}
		md, err := c.ToMarkdown(context.Background(), device)
		require.NoError(t, err)
		assert.NotEmpty(t, md)
		// The markdown should be rendered without error regardless of theme
		assert.Contains(t, md, "OPNsense Configuration")
	})
}

// TestNewMarkdownConverter tests the constructor.
func TestNewMarkdownConverter(t *testing.T) {
	c := NewMarkdownConverter()
	assert.NotNil(t, c)
	assert.IsType(t, &MarkdownConverter{}, c)
}

func TestFormatInterfacesAsLinks(t *testing.T) {
	tests := []struct {
		name       string
		interfaces []string
		expected   string
	}{
		{
			name:       "empty interface list",
			interfaces: []string{},
			expected:   "",
		},
		{
			name:       "single interface",
			interfaces: []string{"wan"},
			expected:   "[wan](#wan-interface)",
		},
		{
			name:       "multiple interfaces",
			interfaces: []string{"wan", "lan", "opt1"},
			expected:   "[wan](#wan-interface), [lan](#lan-interface), [opt1](#opt1-interface)",
		},
		{
			name:       "mixed case interface names",
			interfaces: []string{"WAN", "LAN", "OPT1"},
			expected:   "[WAN](#wan-interface), [LAN](#lan-interface), [OPT1](#opt1-interface)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatters.FormatInterfacesAsLinks(tt.interfaces)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMarkdownConverter_FirewallRulesWithInterfaceLinks(t *testing.T) {
	// Set terminal to dumb for consistent test output
	t.Setenv("TERM", "dumb")

	input := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{
				Type:        "pass",
				Interfaces:  []string{"wan", "lan"},
				IPProtocol:  "inet",
				Protocol:    "tcp",
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "any"},
				Description: "Test rule with multiple interfaces",
			},
			{
				Type:        "block",
				Interfaces:  []string{"opt1"},
				IPProtocol:  "inet",
				Protocol:    "udp",
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "any"},
				Description: "Test rule with single interface",
			},
		},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true, IPAddress: "192.168.1.1"},
			{Name: "lan", Enabled: true, IPAddress: "10.0.0.1"},
			{Name: "opt1", Enabled: true, IPAddress: "172.16.0.1"},
		},
	}

	c := NewMarkdownConverter()
	md, err := c.ToMarkdown(context.Background(), input)
	require.NoError(t, err)

	// Check that interface links are properly formatted in the table
	// The nao1215/markdown package uses reference-style links in tables
	assert.Contains(t, md, "wan[1],")
	assert.Contains(t, md, "lan[2]")
	assert.Contains(t, md, "opt1[3]")

	// Check that the reference links are defined at the bottom
	assert.Contains(t, md, "[1]: wan #wan-interface")
	assert.Contains(t, md, "[2]: lan #lan-interface")
	assert.Contains(t, md, "[3]: opt1 #opt1-interface")

	// Check that interface sections are created (title-cased from Name field)
	assert.Contains(t, md, "### Wan Interface")
	assert.Contains(t, md, "### Lan Interface")
	assert.Contains(t, md, "### Opt1 Interface")
}

// TestMarkdownConverter_IDSSection tests the IDS section in MarkdownConverter output.
func TestMarkdownConverter_IDSSection(t *testing.T) {
	// Set terminal to dumb for consistent test output
	t.Setenv("TERM", "dumb")

	t.Run("IDS enabled shows in output", func(t *testing.T) {
		input := &common.CommonDevice{
			System: common.System{
				Hostname: "ids-test",
				Domain:   "test.local",
			},
			IDS: &common.IDSConfig{
				Enabled:          true,
				IPSMode:          true,
				Interfaces:       []string{"wan", "lan"},
				HomeNetworks:     []string{"192.168.1.0/24", "10.0.0.0/8"},
				Detect:           common.IDSDetect{Profile: "medium"},
				SyslogEnabled:    true,
				SyslogEveEnabled: true,
			},
		}

		c := NewMarkdownConverter()
		md, err := c.ToMarkdown(context.Background(), input)
		require.NoError(t, err)

		// Verify IDS section appears
		assert.Contains(t, md, "Intrusion Detection System")
		assert.Contains(t, md, "IPS")
		assert.Contains(t, md, "wan")
		assert.Contains(t, md, "lan")
		assert.Contains(t, md, "192.168.1.0/24")
		assert.Contains(t, md, "10.0.0.0/8")
		assert.Contains(t, md, "medium")
		assert.Contains(t, md, "Syslog Output")
		// EVE Syslog may wrap across lines in terminal output
		assert.Contains(t, md, "EVE")
	})

	t.Run("IDS disabled not shown", func(t *testing.T) {
		input := &common.CommonDevice{
			System: common.System{
				Hostname: "ids-disabled-test",
				Domain:   "test.local",
			},
			IDS: &common.IDSConfig{
				Enabled: false,
			},
		}

		c := NewMarkdownConverter()
		md, err := c.ToMarkdown(context.Background(), input)
		require.NoError(t, err)

		// Verify IDS section does NOT appear when disabled
		assert.NotContains(t, md, "Intrusion Detection System")
	})

	t.Run("nil IDS not shown", func(t *testing.T) {
		input := &common.CommonDevice{
			System: common.System{
				Hostname: "no-ids-test",
				Domain:   "test.local",
			},
		}

		c := NewMarkdownConverter()
		md, err := c.ToMarkdown(context.Background(), input)
		require.NoError(t, err)

		// Verify IDS section does NOT appear when nil
		assert.NotContains(t, md, "Intrusion Detection System")
	})
}
