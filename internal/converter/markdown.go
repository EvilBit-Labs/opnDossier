// Package converter provides functionality to convert OPNsense configurations to markdown.
//
// Deprecated: Use the markdown.Generator interface instead.
package converter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/charmbracelet/glamour"
	"github.com/nao1215/markdown"
)

// Constants for common values.
const (
	destinationAny = "any"
)

// Converter is the interface for converting OPNsense configurations to markdown.
type Converter interface {
	ToMarkdown(ctx context.Context, opnsense *model.OpnSenseDocument) (string, error)
}

// MarkdownConverter is a markdown converter for OPNsense configurations.
//
// Deprecated: Use the markdown.Generator interface instead.
type MarkdownConverter struct{}

// NewMarkdownConverter creates and returns a new MarkdownConverter for converting OPNsense configuration data to markdown format.
func NewMarkdownConverter() *MarkdownConverter {
	return &MarkdownConverter{}
}

// ErrNilOpnSenseDocument is returned when the input OpnSenseDocument struct is nil.
var ErrNilOpnSenseDocument = errors.New("input OpnSenseDocument struct is nil")

// ErrUnsupportedFormat is returned when an unsupported output format is requested.
var ErrUnsupportedFormat = errors.New("unsupported format. Supported formats: markdown, json, yaml")

// ToMarkdown converts an OPNsense configuration to markdown.
func (c *MarkdownConverter) ToMarkdown(_ context.Context, opnsense *model.OpnSenseDocument) (string, error) {
	if opnsense == nil {
		return "", ErrNilOpnSenseDocument
	}

	// Create markdown using github.com/nao1215/markdown for structured output
	var buf bytes.Buffer

	md := markdown.NewMarkdown(&buf)

	// Main title
	md.H1("OPNsense Configuration")

	// System Configuration
	c.buildSystemSection(md, opnsense)

	// Network Configuration
	c.buildNetworkSection(md, opnsense)

	// Security Configuration
	c.buildSecuritySection(md, opnsense)

	// Service Configuration
	c.buildServiceSection(md, opnsense)

	// Get the raw markdown content
	rawMarkdown := md.String()

	// Use glamour for terminal rendering with theme compatibility
	theme := c.getTheme()

	r, err := glamour.Render(rawMarkdown, theme)
	if err != nil {
		return "", fmt.Errorf("failed to render markdown: %w", err)
	}

	return r, nil
}

// getTheme determines the appropriate theme based on environment variables and terminal settings.
func (c *MarkdownConverter) getTheme() string {
	// Check for explicit theme preference
	if theme := os.Getenv("OPNDOSSIER_THEME"); theme != "" {
		return theme
	}

	// Check for dark mode indicators
	if colorTerm := os.Getenv("COLORTERM"); colorTerm == "truecolor" {
		if term := os.Getenv("TERM"); strings.Contains(term, "256") {
			return "dark"
		}
	}

	// Default to auto which will detect based on terminal
	return "auto"
}

// buildSystemSection builds the system configuration section using helper methods.
func (c *MarkdownConverter) buildSystemSection(md *markdown.Markdown, opnsense *model.OpnSenseDocument) {
	sysConfig := opnsense.SystemConfig()

	md.H2("System Configuration")

	c.buildBasicInfo(md, &sysConfig)
	c.buildWebGUI(md, &sysConfig)
	c.buildSysctl(md, &sysConfig)
	c.buildUsers(md, &sysConfig)
	c.buildGroups(md, &sysConfig)
}

// buildBasicInfo builds the basic system information section.
func (c *MarkdownConverter) buildBasicInfo(md *markdown.Markdown, sysConfig *model.SystemConfig) {
	// Basic system information
	md.H3("Basic Information")
	md.PlainTextf("%s: %s", markdown.Bold("Hostname"), sysConfig.System.Hostname)
	md.PlainTextf("%s: %s", markdown.Bold("Domain"), sysConfig.System.Domain)

	if sysConfig.System.Timezone != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Timezone"), sysConfig.System.Timezone)
	}

	if sysConfig.System.Optimization != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Optimization"), sysConfig.System.Optimization)
	}
}

// buildWebGUI builds the WebGUI configuration section.
func (c *MarkdownConverter) buildWebGUI(md *markdown.Markdown, sysConfig *model.SystemConfig) {
	if sysConfig.System.WebGUI.Protocol != "" {
		md.H3("Web GUI")
		md.PlainTextf("%s: %s", markdown.Bold("Protocol"), sysConfig.System.WebGUI.Protocol)
	}
}

// buildSysctl builds the sysctl configuration as a table.
func (c *MarkdownConverter) buildSysctl(md *markdown.Markdown, sysConfig *model.SystemConfig) {
	if len(sysConfig.Sysctl) > 0 {
		md.H3("System Tuning")

		headers := []string{"Tunable", "Value", "Description"}

		rows := make([][]string, 0, len(sysConfig.Sysctl))
		for _, item := range sysConfig.Sysctl {
			rows = append(rows, []string{item.Tunable, item.Value, item.Descr})
		}

		tableSet := markdown.TableSet{
			Header: headers,
			Rows:   rows,
		}
		md.Table(tableSet)
	}
}

// buildUsers builds the users configuration as a table.
func (c *MarkdownConverter) buildUsers(md *markdown.Markdown, sysConfig *model.SystemConfig) {
	if len(sysConfig.System.User) > 0 {
		md.H3("Users")

		headers := []string{"Name", "Description", "Group", "Scope"}

		rows := make([][]string, 0, len(sysConfig.System.User))
		for _, user := range sysConfig.System.User {
			rows = append(rows, []string{user.Name, user.Descr, user.Groupname, user.Scope})
		}

		tableSet := markdown.TableSet{
			Header: headers,
			Rows:   rows,
		}
		md.Table(tableSet)
	}
}

// buildGroups builds the groups configuration as a table.
func (c *MarkdownConverter) buildGroups(md *markdown.Markdown, sysConfig *model.SystemConfig) {
	if len(sysConfig.System.Group) > 0 {
		md.H3("Groups")

		headers := []string{"Name", "Description", "Scope"}

		rows := make([][]string, 0, len(sysConfig.System.Group))
		for _, group := range sysConfig.System.Group {
			rows = append(rows, []string{group.Name, group.Description, group.Scope})
		}

		tableSet := markdown.TableSet{
			Header: headers,
			Rows:   rows,
		}
		md.Table(tableSet)
	}
}

// buildNetworkSection builds the network configuration section using helper methods.
func (c *MarkdownConverter) buildNetworkSection(md *markdown.Markdown, opnsense *model.OpnSenseDocument) {
	netConfig := opnsense.NetworkConfig()

	md.H2("Network Configuration")

	// WAN Interface
	md.H3("WAN Interface")

	if wan, ok := netConfig.Interfaces.Wan(); ok {
		c.buildInterfaceDetails(md, wan)
	}

	// LAN Interface
	md.H3("LAN Interface")

	if lan, ok := netConfig.Interfaces.Lan(); ok {
		c.buildInterfaceDetails(md, lan)
	}
}

// buildInterfaceDetails builds interface configuration details.
func (c *MarkdownConverter) buildInterfaceDetails(md *markdown.Markdown, iface model.Interface) {
	if iface.If != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Physical Interface"), iface.If)
	}

	if iface.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Enabled"), iface.Enable)
	}

	if iface.IPAddr != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv4 Address"), iface.IPAddr)
	}

	if iface.Subnet != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv4 Subnet"), iface.Subnet)
	}

	if iface.IPAddrv6 != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv6 Address"), iface.IPAddrv6)
	}

	if iface.Subnetv6 != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv6 Subnet"), iface.Subnetv6)
	}

	if iface.Gateway != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Gateway"), iface.Gateway)
	}

	if iface.MTU != "" {
		md.PlainTextf("%s: %s", markdown.Bold("MTU"), iface.MTU)
	}

	if iface.BlockPriv != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Block Private Networks"), iface.BlockPriv)
	}

	if iface.BlockBogons != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Block Bogon Networks"), iface.BlockBogons)
	}
}

// buildSecuritySection builds the security configuration section using helper methods.
func (c *MarkdownConverter) buildSecuritySection(md *markdown.Markdown, opnsense *model.OpnSenseDocument) {
	secConfig := opnsense.SecurityConfig()

	md.H2("Security Configuration")

	// NAT Configuration
	md.H3("NAT Configuration")

	if secConfig.Nat.Outbound.Mode != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Outbound NAT Mode"), secConfig.Nat.Outbound.Mode)
	}

	// Firewall Rules
	rules := opnsense.FilterRules()
	if len(rules) > 0 {
		md.H3("Firewall Rules")

		headers := []string{"Type", "Interface", "Protocol", "Source", "Destination", "Description"}

		rows := make([][]string, 0, len(rules))
		for _, rule := range rules {
			source := rule.Source.Network
			if source == "" {
				source = destinationAny
			}

			// Check destination - can be either Network or Any
			dest := rule.Destination.Network
			if dest == "" {
				// If no network is specified, check if it's any destination
				// Since Any is a struct{}, we'll assume it's "any" if Network is empty
				dest = destinationAny
			}

			rows = append(rows, []string{
				rule.Type,
				rule.Interface.String(),
				rule.IPProtocol,
				source,
				dest,
				rule.Descr,
			})
		}

		tableSet := markdown.TableSet{
			Header: headers,
			Rows:   rows,
		}
		md.Table(tableSet)
	}
}

// buildServiceSection builds the service configuration section using helper methods.
func (c *MarkdownConverter) buildServiceSection(md *markdown.Markdown, opnsense *model.OpnSenseDocument) {
	svcConfig := opnsense.ServiceConfig()

	md.H2("Service Configuration")

	// DHCP Server
	md.H3("DHCP Server")

	if lanDhcp, ok := svcConfig.Dhcpd.Get("lan"); ok && lanDhcp.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("LAN DHCP Enabled"), lanDhcp.Enable)

		if lanDhcp.Range.From != "" && lanDhcp.Range.To != "" {
			md.PlainTextf("%s: %s - %s", markdown.Bold("LAN DHCP Range"), lanDhcp.Range.From, lanDhcp.Range.To)
		}
	}

	if wanDhcp, ok := svcConfig.Dhcpd.Get("wan"); ok && wanDhcp.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("WAN DHCP Enabled"), wanDhcp.Enable)
	}

	// DNS Resolver (Unbound)
	md.H3("DNS Resolver (Unbound)")

	if svcConfig.Unbound.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Enabled"), svcConfig.Unbound.Enable)
	}

	// SNMP
	md.H3("SNMP")

	if svcConfig.Snmpd.SysLocation != "" {
		md.PlainTextf("%s: %s", markdown.Bold("System Location"), svcConfig.Snmpd.SysLocation)
	}

	if svcConfig.Snmpd.SysContact != "" {
		md.PlainTextf("%s: %s", markdown.Bold("System Contact"), svcConfig.Snmpd.SysContact)
	}

	if svcConfig.Snmpd.ROCommunity != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Read-Only Community"), svcConfig.Snmpd.ROCommunity)
	}

	// NTP
	md.H3("NTP")

	if svcConfig.Ntpd.Prefer != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Preferred Server"), svcConfig.Ntpd.Prefer)
	}

	// Load Balancer
	if len(svcConfig.LoadBalancer.MonitorType) > 0 {
		md.H3("Load Balancer Monitors")

		headers := []string{"Name", "Type", "Description"}

		rows := make([][]string, 0, len(svcConfig.LoadBalancer.MonitorType))
		for _, monitor := range svcConfig.LoadBalancer.MonitorType {
			rows = append(rows, []string{monitor.Name, monitor.Type, monitor.Descr})
		}

		tableSet := markdown.TableSet{
			Header: headers,
			Rows:   rows,
		}
		md.Table(tableSet)
	}
}
