package markdown

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/unclesp1d3r/opnFocus/internal/model"

	"github.com/charmbracelet/glamour"
	"github.com/nao1215/markdown"
	"gopkg.in/yaml.v3"
)

// Generator represents the interface for generating documentation from OPNsense configurations.
type Generator interface {
	// Generate creates documentation in a specified format from the provided OPNsense configuration.
	Generate(ctx context.Context, cfg *model.Opnsense, opts Options) (string, error)
}

// Standalone wrapper functions for section renderers

// sectionBuilder is a type for building different sections.
type sectionBuilder func(md *markdown.Markdown, opnsense *model.Opnsense)

// buildSystemSection is a wrapper for the system section renderer.
func buildSystemSection(md *markdown.Markdown, opnsense *model.Opnsense) {
	g := markdownGenerator{}
	g.buildSystemSection(md, opnsense)
}

// buildNetworkSection is a wrapper for the network section renderer.
func buildNetworkSection(md *markdown.Markdown, opnsense *model.Opnsense) {
	g := markdownGenerator{}
	g.buildNetworkSection(md, opnsense)
}

// buildSecuritySection is a wrapper for the security section renderer.
func buildSecuritySection(md *markdown.Markdown, opnsense *model.Opnsense) {
	g := markdownGenerator{}
	g.buildSecuritySection(md, opnsense)
}

// buildServiceSection is a wrapper for the service section renderer.
func buildServiceSection(md *markdown.Markdown, opnsense *model.Opnsense) {
	g := markdownGenerator{}
	g.buildServiceSection(md, opnsense)
}

// markdownGenerator is the default implementation that wraps the old Markdown logic.
type markdownGenerator struct{}

// NewMarkdownGenerator returns an instance of the default markdownGenerator implementation.
func NewMarkdownGenerator() Generator {
	return markdownGenerator{}
}

// Generate converts an OPNsense configuration to the specified format using the Options provided.
func (g markdownGenerator) Generate(ctx context.Context, cfg *model.Opnsense, opts Options) (string, error) {
	if cfg == nil {
		return "", ErrNilConfiguration
	}

	if err := opts.Validate(); err != nil {
		return "", fmt.Errorf("invalid options: %w", err)
	}

	switch opts.Format {
	case FormatMarkdown:
		return g.generateMarkdown(ctx, cfg, opts)

	case FormatJSON:
		return g.generateJSON(ctx, cfg, opts)

	case FormatYAML:
		return g.generateYAML(ctx, cfg, opts)

	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
	}
}

// SectionRenderer represents a function that renders a configuration section.
type SectionRenderer func(md *markdown.Markdown, cfg *model.Opnsense)

// sectionRenderers holds functions that render each section, associated by name.
// This map can be extended by other packages to register new sections.
var sectionRenderers = make(map[string]SectionRenderer)

// init registers the default section renderers.
func init() {
	RegisterSectionRenderer("system", buildSystemSection)
	RegisterSectionRenderer("network", buildNetworkSection)
	RegisterSectionRenderer("security", buildSecuritySection)
	RegisterSectionRenderer("service", buildServiceSection)
}

// RegisterSectionRenderer registers a new section renderer.
// This allows other packages to extend functionality without modifying core code.
func RegisterSectionRenderer(name string, renderer SectionRenderer) {
	sectionRenderers[name] = renderer
}

// sectionOrder defines the logical order for building sections.
// The order is: system, network, security, services.
// This ensures consistent output and proper documentation flow:
// 1. System - Basic configuration and platform settings
// 2. Network - Interface and networking configuration
// 3. Security - Firewall rules, NAT, and security policies
// 4. Services - Application services and daemon configurations.
var sectionOrder = []sectionBuilder{
	buildSystemSection,
	buildNetworkSection,
	buildSecuritySection,
	buildServiceSection,
}

// generateMarkdown generates markdown output using the existing logic.
func (g markdownGenerator) generateMarkdown(ctx context.Context, cfg *model.Opnsense, opts Options) (string, error) {
	// Create markdown using github.com/nao1215/markdown for structured output
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	// Main title
	md.H1("OPNsense Configuration")

	// Build sections in the defined logical order
	for _, builder := range sectionOrder {
		builder(md, cfg)
	}

	// Get the raw markdown content
	rawMarkdown := md.String()

	// Use glamour for terminal rendering with theme compatibility
	theme := g.getTheme(opts)
	r, err := glamour.Render(rawMarkdown, theme)
	if err != nil {
		return "", fmt.Errorf("failed to render markdown: %w", err)
	}

	return r, nil
}

// generateJSON generates JSON output.
func (g markdownGenerator) generateJSON(ctx context.Context, cfg *model.Opnsense, opts Options) (string, error) {
	// Marshal the Opnsense struct to JSON with indentation
	jsonBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal to JSON: %w", err)
	}

	return string(jsonBytes), nil
}

// generateYAML generates YAML output.
func (g markdownGenerator) generateYAML(ctx context.Context, cfg *model.Opnsense, opts Options) (string, error) {
	// Marshal the Opnsense struct to YAML
	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal to YAML: %w", err)
	}

	return string(yamlBytes), nil
}

// getTheme determines the appropriate theme based on the options provided.
func (g markdownGenerator) getTheme(opts Options) string {
	// Check for explicit theme preference in options
	if opts.Theme != "" {
		return opts.Theme.String()
	}

	// Default to auto which will detect based on terminal
	return "auto"
}

// buildSystemSection builds the system configuration section using helper methods.
func (g markdownGenerator) buildSystemSection(md *markdown.Markdown, opnsense *model.Opnsense) {
	sysConfig := opnsense.SystemConfig()
	md.H2("System Configuration")

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

	// DNS and Network Configuration
	if sysConfig.System.DNSAllowOverride != "" {
		md.PlainTextf("%s: %s", markdown.Bold("DNS Allow Override"), sysConfig.System.DNSAllowOverride)
	}
	if sysConfig.System.Timeservers != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Time Servers"), sysConfig.System.Timeservers)
	}

	// Web GUI configuration
	if sysConfig.System.Webgui.Protocol != "" {
		md.H3("Web GUI")
		md.PlainTextf("%s: %s", markdown.Bold("Protocol"), sysConfig.System.Webgui.Protocol)
	}

	// Hardware Offloading Settings
	md.H3("Hardware Settings")
	if sysConfig.System.DisableNATReflection != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Disable NAT Reflection"), sysConfig.System.DisableNATReflection)
	}
	if sysConfig.System.UseVirtualTerminal != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Use Virtual Terminal"), sysConfig.System.UseVirtualTerminal)
	}
	if sysConfig.System.DisableVLANHWFilter != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Disable VLAN HW Filter"), sysConfig.System.DisableVLANHWFilter)
	}
	if sysConfig.System.DisableChecksumOffloading != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Disable Checksum Offloading"), sysConfig.System.DisableChecksumOffloading)
	}
	if sysConfig.System.DisableSegmentationOffloading != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Disable Segmentation Offloading"), sysConfig.System.DisableSegmentationOffloading)
	}
	if sysConfig.System.DisableLargeReceiveOffloading != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Disable Large Receive Offloading"), sysConfig.System.DisableLargeReceiveOffloading)
	}

	// Power Management (PowerD)
	if sysConfig.System.PowerdAcMode != "" || sysConfig.System.PowerdBatteryMode != "" || sysConfig.System.PowerdNormalMode != "" {
		md.H3("Power Management")
		if sysConfig.System.PowerdAcMode != "" {
			md.PlainTextf("%s: %s", markdown.Bold("PowerD AC Mode"), sysConfig.System.PowerdAcMode)
		}
		if sysConfig.System.PowerdBatteryMode != "" {
			md.PlainTextf("%s: %s", markdown.Bold("PowerD Battery Mode"), sysConfig.System.PowerdBatteryMode)
		}
		if sysConfig.System.PowerdNormalMode != "" {
			md.PlainTextf("%s: %s", markdown.Bold("PowerD Normal Mode"), sysConfig.System.PowerdNormalMode)
		}
	}

	// Bogons Configuration
	if sysConfig.System.Bogons.Interval != "" {
		md.H3("Bogons Configuration")
		md.PlainTextf("%s: %s", markdown.Bold("Update Interval"), sysConfig.System.Bogons.Interval)
	}

	// SSH Configuration
	if sysConfig.System.SSH.Group != "" {
		md.H3("SSH Configuration")
		md.PlainTextf("%s: %s", markdown.Bold("Authorized Group"), sysConfig.System.SSH.Group)
	}

	// Backup and Logging Settings
	if sysConfig.System.RrdBackup != "" || sysConfig.System.NetflowBackup != "" {
		md.H3("Backup and Logging")
		if sysConfig.System.RrdBackup != "" {
			md.PlainTextf("%s: %s", markdown.Bold("RRD Backup"), sysConfig.System.RrdBackup)
		}
		if sysConfig.System.NetflowBackup != "" {
			md.PlainTextf("%s: %s", markdown.Bold("Netflow Backup"), sysConfig.System.NetflowBackup)
		}
	}

	// System tuning (sysctl) - Enhanced with enabled state
	if len(sysConfig.Sysctl) > 0 {
		md.H3("System Tuning (Sysctl)")
		// Use unordered list format as requested
		for _, item := range sysConfig.Sysctl {
			// Since the SysctlItem struct doesn't have an Enabled field in the current model,
			// we consider all items as enabled if they exist in the configuration
			enabledState := "enabled"
			md.PlainTextf("• **%s**: %s", item.Tunable, item.Value)
			if item.Descr != "" {
				md.PlainTextf("  - *Description*: %s", item.Descr)
			}
			md.PlainTextf("  - *Status*: %s", enabledState)
		}
	}

	// Users and groups
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
func (g markdownGenerator) buildNetworkSection(md *markdown.Markdown, opnsense *model.Opnsense) {
	netConfig := opnsense.NetworkConfig()
	md.H2("Network Configuration")

	// WAN Interface
	md.H3("WAN Interface")
	if wan, ok := netConfig.Interfaces.Wan(); ok {
		g.buildInterfaceDetails(md, wan)
	}

	// LAN Interface
	md.H3("LAN Interface")
	if lan, ok := netConfig.Interfaces.Lan(); ok {
		g.buildInterfaceDetails(md, lan)
	}
}

// buildInterfaceDetails builds interface configuration details.
func (g markdownGenerator) buildInterfaceDetails(md *markdown.Markdown, iface model.Interface) {
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
func (g markdownGenerator) buildSecuritySection(md *markdown.Markdown, opnsense *model.Opnsense) {
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
				source = "any"
			}

			// Check destination - can be either Network or Any
			dest := rule.Destination.Network
			if dest == "" {
				dest = "any"
			}

			rows = append(rows, []string{
				rule.Type,
				rule.Interface,
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
func (g markdownGenerator) buildServiceSection(md *markdown.Markdown, opnsense *model.Opnsense) {
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
