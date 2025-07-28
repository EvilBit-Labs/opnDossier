package converter

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unclesp1d3r/opnFocus/internal/model"
	"github.com/unclesp1d3r/opnFocus/internal/parser"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ansiStripper = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiStripper.ReplaceAllString(s, "")
}

func TestMarkdownConverter_ToMarkdown(t *testing.T) {
	tests := []struct {
		name     string
		input    *model.Opnsense
		expected string
		wantErr  bool
	}{
		{
			name: "basic conversion",
			input: &model.Opnsense{
				Version: "1.2.3",
				System: model.System{
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
			input:    &model.Opnsense{},
			expected: "OPNsense Configuration",
			wantErr:  false,
		},
		{
			name: "missing system fields",
			input: &model.Opnsense{
				System: model.System{},
			},
			expected: "OPNsense Configuration",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewMarkdownConverter()
			md, err := c.ToMarkdown(context.Background(), tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, md)
			} else {
				assert.NoError(t, err)

				actual := strings.TrimSpace(stripANSI(md))
				assert.Contains(t, actual, "OPNsense Configuration")
				assert.Contains(t, actual, "## System")

				if tt.input != nil && tt.input.System.Hostname != "" && tt.input.System.Domain != "" {
					assert.Contains(t, actual, "Hostname: "+tt.input.System.Hostname+" Domain: "+tt.input.System.Domain)
				}
			}
		})
	}
}

// TestMarkdownConverter_ConvertFromTestdataFile tests conversion of the complete testdata file.
func TestMarkdownConverter_ConvertFromTestdataFile(t *testing.T) {
	// Read the sample XML file
	xmlPath := filepath.Join("..", "..", "testdata", "sample.config.3.xml")
	xmlData, err := os.ReadFile(xmlPath)
	require.NoError(t, err, "Failed to read testdata XML file")

	// Parse the XML file using the parser
	p := parser.NewXMLParser()
	opnsense, err := p.Parse(context.Background(), strings.NewReader(string(xmlData)))
	require.NoError(t, err, "XML parsing should succeed")

	// Convert to markdown
	c := NewMarkdownConverter()
	markdown, err := c.ToMarkdown(context.Background(), opnsense)
	require.NoError(t, err, "Markdown conversion should succeed")

	// Verify the markdown is not empty
	assert.NotEmpty(t, markdown, "Markdown output should not be empty")

	// Strip ANSI codes for easier testing
	cleanMarkdown := stripANSI(markdown)

	// Verify main sections are present
	assert.Contains(t, cleanMarkdown, "OPNsense Configuration")
	assert.Contains(t, cleanMarkdown, "## System Configuration")
	assert.Contains(t, cleanMarkdown, "## Network Configuration")
	assert.Contains(t, cleanMarkdown, "## Security Configuration")
	assert.Contains(t, cleanMarkdown, "## Service Configuration")

	// Verify system information
	assert.Contains(t, cleanMarkdown, "Hostname: OPNsense")
	assert.Contains(t, cleanMarkdown, "Domain: localdomain")
	assert.Contains(t, cleanMarkdown, "Optimization:")
	assert.Contains(t, cleanMarkdown, "normal")
	assert.Contains(t, cleanMarkdown, "Protocol: https")

	// Verify network interfaces
	assert.Contains(t, cleanMarkdown, "## WAN Interface")
	assert.Contains(t, cleanMarkdown, "## LAN Interface")
	assert.Contains(t, cleanMarkdown, "Physical Interface: mismatch1")
	assert.Contains(t, cleanMarkdown, "Physical Interface: mismatch0")
	assert.Contains(t, cleanMarkdown, "IPv4 Address: dhcp")
	assert.Contains(t, cleanMarkdown, "IPv4 Address: 192.168.1.1")

	// Verify security configuration
	assert.Contains(t, cleanMarkdown, "NAT Configuration")
	assert.Contains(t, cleanMarkdown, "Outbound NAT Mode: automatic")
	assert.Contains(t, cleanMarkdown, "Firewall Rules")

	// Verify service configuration
	assert.Contains(t, cleanMarkdown, "DHCP Server")
	assert.Contains(t, cleanMarkdown, "DNS Resolver (Unbound)")
	assert.Contains(t, cleanMarkdown, "SNMP")
	assert.Contains(t, cleanMarkdown, "Read-Only Community: public")

	// Verify tables are rendered
	assert.Contains(t, cleanMarkdown, "TUNABLE")
	assert.Contains(t, cleanMarkdown, "VALUE")
	assert.Contains(t, cleanMarkdown, "DESCRIPTION")

	// Verify users and groups tables
	assert.Contains(t, cleanMarkdown, "Users")
	assert.Contains(t, cleanMarkdown, "Groups")
	assert.Contains(t, cleanMarkdown, "root")
	assert.Contains(t, cleanMarkdown, "admins")

	// Verify firewall rules table
	assert.Contains(t, cleanMarkdown, "TYPE")
	assert.Contains(t, cleanMarkdown, "INT")
	assert.Contains(t, cleanMarkdown, "PROTO")
	assert.Contains(t, cleanMarkdown, "SOUR")
	assert.Contains(t, cleanMarkdown, "DEST")

	// Verify load balancer monitors
	assert.Contains(t, cleanMarkdown, "Load Balancer Monitors")
	assert.Contains(t, cleanMarkdown, "ICMP")
	assert.Contains(t, cleanMarkdown, "HTTP")
}

// TestMarkdownConverter_EdgeCases tests edge cases and error conditions.
func TestMarkdownConverter_EdgeCases(t *testing.T) {
	c := NewMarkdownConverter()

	t.Run("nil opnsense struct", func(t *testing.T) {
		md, err := c.ToMarkdown(context.Background(), nil)
		assert.Error(t, err)
		assert.Equal(t, ErrNilOpnsense, err)
		assert.Empty(t, md)
	})

	t.Run("empty opnsense struct", func(t *testing.T) {
		md, err := c.ToMarkdown(context.Background(), &model.Opnsense{})
		assert.NoError(t, err)
		assert.NotEmpty(t, md)
		assert.Contains(t, stripANSI(md), "OPNsense Configuration")
	})

	t.Run("opnsense with only system configuration", func(t *testing.T) {
		opnsense := &model.Opnsense{
			System: model.System{
				Hostname: "test-host",
				Domain:   "test.local",
				Webgui:   model.Webgui{Protocol: "http"},
			},
		}
		md, err := c.ToMarkdown(context.Background(), opnsense)
		assert.NoError(t, err)
		assert.NotEmpty(t, md)

		cleanMd := stripANSI(md)
		assert.Contains(t, cleanMd, "Hostname: test-host")
		assert.Contains(t, cleanMd, "Domain: test.local")
		assert.Contains(t, cleanMd, "Protocol: http")
	})

	t.Run("opnsense with complex sysctl configuration", func(t *testing.T) {
		opnsense := &model.Opnsense{
			System: model.System{
				Hostname: "sysctl-test",
				Domain:   "test.local",
			},
			Sysctl: []model.SysctlItem{
				{
					Tunable: "net.inet.ip.forwarding",
					Value:   "1",
					Descr:   "Enable IP forwarding",
				},
				{
					Tunable: "kern.ipc.somaxconn",
					Value:   "1024",
					Descr:   "Maximum socket connections",
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), opnsense)
		assert.NoError(t, err)
		assert.NotEmpty(t, md)

		cleanMd := stripANSI(md)
		assert.Contains(t, cleanMd, "System Tuning")
		assert.Contains(t, cleanMd, "net.inet.ip.forwarding")
		assert.Contains(t, cleanMd, "kern.ipc.somaxconn")
		assert.Contains(t, cleanMd, "Enable IP forwarding")
		assert.Contains(t, cleanMd, "Maximum socket connections")
	})

	t.Run("opnsense with users and groups", func(t *testing.T) {
		opnsense := &model.Opnsense{
			System: model.System{
				Hostname: "user-test",
				Domain:   "test.local",
				User: []model.User{
					{
						Name:      "admin",
						Descr:     "Administrator",
						Groupname: "wheel",
						Scope:     "system",
					},
				},
				Group: []model.Group{
					{
						Name:        "wheel",
						Description: "Wheel Group",
						Scope:       "system",
					},
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), opnsense)
		assert.NoError(t, err)
		assert.NotEmpty(t, md)

		cleanMd := stripANSI(md)
		assert.Contains(t, cleanMd, "Users")
		assert.Contains(t, cleanMd, "Groups")
		assert.Contains(t, cleanMd, "admin")
		assert.Contains(t, cleanMd, "wheel")
		assert.Contains(t, cleanMd, "Administrator")
		assert.Contains(t, cleanMd, "Wheel Group")
	})

	t.Run("opnsense with multiple firewall rules", func(t *testing.T) {
		opnsense := &model.Opnsense{
			System: model.System{
				Hostname: "firewall-test",
				Domain:   "test.local",
			},
			Filter: model.Filter{
				Rule: []model.Rule{
					{
						Type:       "pass",
						Interface:  "lan",
						IPProtocol: "inet",
						Descr:      "Allow LAN",
						Source:     model.Source{Network: "lan"},
					},
					{
						Type:       "block",
						Interface:  "wan",
						IPProtocol: "inet",
						Descr:      "Block external",
						Source:     model.Source{Network: "any"},
					},
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), opnsense)
		assert.NoError(t, err)
		assert.NotEmpty(t, md)

		cleanMd := stripANSI(md)
		assert.Contains(t, cleanMd, "Firewall Rules")
		assert.Contains(t, cleanMd, "Allow LAN")
		assert.Contains(t, cleanMd, "Block external")
		assert.Contains(t, cleanMd, "pass")
		assert.Contains(t, cleanMd, "block")
	})

	t.Run("opnsense with load balancer monitors", func(t *testing.T) {
		opnsense := &model.Opnsense{
			System: model.System{
				Hostname: "lb-test",
				Domain:   "test.local",
			},
			LoadBalancer: model.LoadBalancer{
				MonitorType: []model.MonitorType{
					{
						Name:  "TCP-80",
						Type:  "tcp",
						Descr: "TCP port 80 check",
					},
					{
						Name:  "HTTPS-443",
						Type:  "https",
						Descr: "HTTPS health check",
					},
				},
			},
		}
		md, err := c.ToMarkdown(context.Background(), opnsense)
		assert.NoError(t, err)
		assert.NotEmpty(t, md)

		cleanMd := stripANSI(md)
		assert.Contains(t, cleanMd, "Load Balancer Monitors")
		assert.Contains(t, cleanMd, "TCP-80")
		assert.Contains(t, cleanMd, "HTTPS-443")
		assert.Contains(t, cleanMd, "TCP port 80 check")
		assert.Contains(t, cleanMd, "HTTPS health check")
	})
}

// TestMarkdownConverter_ThemeSelection tests theme selection logic.
func TestMarkdownConverter_ThemeSelection(t *testing.T) {
	c := NewMarkdownConverter()

	t.Run("default theme selection", func(t *testing.T) {
		// Test the getTheme method indirectly through ToMarkdown
		opnsense := &model.Opnsense{
			System: model.System{
				Hostname: "theme-test",
				Domain:   "test.local",
			},
		}
		md, err := c.ToMarkdown(context.Background(), opnsense)
		assert.NoError(t, err)
		assert.NotEmpty(t, md)
		// The markdown should be rendered without error regardless of theme
		assert.Contains(t, stripANSI(md), "OPNsense Configuration")
	})
}

// TestNewMarkdownConverter tests the constructor.
func TestNewMarkdownConverter(t *testing.T) {
	c := NewMarkdownConverter()
	assert.NotNil(t, c)
	assert.IsType(t, &MarkdownConverter{}, c)
}
