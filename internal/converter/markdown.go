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
	"strconv"
	"strings"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/charmbracelet/glamour"
	"github.com/nao1215/markdown"
)

// Constants for common values.
const (
	destinationAny = "any"
	checkmark      = "✓"
	xMark          = "✗"
)

// Converter is the interface for converting OPNsense configurations to markdown.
type Converter interface {
	ToMarkdown(ctx context.Context, opnsense *model.OpnSenseDocument) (string, error)
}

// ReportBuilder interface defines the contract for programmatic report generation.
// This provides type-safe, compile-time guaranteed markdown generation.
type ReportBuilder interface {
	// Core section builders
	BuildSystemSection(data *model.OpnSenseDocument) string
	BuildNetworkSection(data *model.OpnSenseDocument) string
	BuildSecuritySection(data *model.OpnSenseDocument) string
	BuildServicesSection(data *model.OpnSenseDocument) string

	// Shared component builders
	BuildFirewallRulesTable(rules []model.Rule) *markdown.TableSet
	BuildInterfaceTable(interfaces model.Interfaces) *markdown.TableSet
	BuildUserTable(users []model.User) *markdown.TableSet
	BuildGroupTable(groups []model.Group) *markdown.TableSet
	BuildSysctlTable(sysctl []model.SysctlItem) *markdown.TableSet

	// Report generation
	BuildStandardReport(data *model.OpnSenseDocument) (string, error)
	BuildComprehensiveReport(data *model.OpnSenseDocument) (string, error)
}

// MarkdownBuilder implements the ReportBuilder interface with comprehensive
// programmatic markdown generation capabilities.
type MarkdownBuilder struct {
	generated   time.Time
	toolVersion string
}

// NewMarkdownBuilder creates a new MarkdownBuilder instance.
func NewMarkdownBuilder() *MarkdownBuilder {
	return &MarkdownBuilder{
		generated:   time.Now(),
		toolVersion: constants.Version,
	}
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

// formatInterfacesAsLinks formats a list of interfaces as markdown links pointing to their respective sections.
// Each interface name is converted to a clickable link that references the corresponding interface configuration section.
// The function returns inline markdown links (e.g., [wan](#wan-interface)), which the nao1215/markdown package
// automatically converts to reference-style links when used in table cells.
func formatInterfacesAsLinks(interfaces model.InterfaceList) string {
	if interfaces.IsEmpty() {
		return ""
	}

	// Create inline markdown links for each interface
	// The nao1215/markdown package will automatically convert these to reference-style links
	// when used in table cells (e.g., wan[1] with [1]: wan #wan-interface at the bottom)
	links := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		// Create anchor link to the interface section
		anchor := "#" + strings.ToLower(iface) + "-interface"

		// Use markdown.Link to create the hyperlink
		links = append(links, markdown.Link(iface, anchor))
	}

	// Join links with comma and space for inline display in table
	return strings.Join(links, ", ")
}

// formatBoolean formats a boolean value for display in markdown tables.
func formatBoolean(value string) string {
	if value == "1" || value == "true" || value == "on" {
		return checkmark
	}
	return xMark
}

// formatBooleanInverted formats a boolean value for display in markdown tables with inverted logic.
// This is used for fields like "Disabled" where empty/0 means enabled and 1 means disabled.
func formatBooleanInverted(value string) string {
	if value == "1" || value == "true" || value == "on" {
		return xMark
	}
	return checkmark
}

// formatIntBoolean formats an integer boolean value for display in markdown tables.
func formatIntBoolean(value int) string {
	if value == 1 {
		return checkmark
	}
	return xMark
}

// formatIntBooleanWithUnset formats an integer boolean value with support for unset states.
func formatIntBooleanWithUnset(value int) string {
	if value == 0 {
		return "unset"
	}
	return formatIntBoolean(value)
}

// formatStructBoolean formats a struct{} boolean value for display in markdown tables.
func formatStructBoolean(_ struct{}) string {
	// If the struct is present, it's considered enabled
	return checkmark
}

// formatBool formats a boolean value for display in markdown tables.
func formatBool(value bool) string {
	if value {
		return checkmark
	}
	return xMark
}

// getPowerModeDescription returns a human-readable description of power management modes.
func getPowerModeDescription(mode string) string {
	switch mode {
	case "hadp":
		return "Adaptive (hadp)"
	case "maximum":
		return "Maximum Performance (maximum)"
	case "minimum":
		return "Minimum Power (minimum)"
	case "hiadaptive":
		return "High Adaptive (hiadaptive)"
	case "adaptive":
		return "Adaptive (adaptive)"
	default:
		return mode
	}
}

// BuildSystemSection builds the system configuration section.
func (b *MarkdownBuilder) BuildSystemSection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	sysConfig := data.SystemConfig()

	md.H2("System Configuration")

	// Basic Information
	md.H3("Basic Information")
	md.PlainTextf("%s: %s", markdown.Bold("Hostname"), sysConfig.System.Hostname)
	md.PlainTextf("%s: %s", markdown.Bold("Domain"), sysConfig.System.Domain)

	if sysConfig.System.Optimization != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Optimization"), sysConfig.System.Optimization)
	}

	if sysConfig.System.Timezone != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Timezone"), sysConfig.System.Timezone)
	}

	if sysConfig.System.Language != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Language"), sysConfig.System.Language)
	}

	// Web GUI Configuration
	if sysConfig.System.WebGUI.Protocol != "" {
		md.H3("Web GUI Configuration")
		md.PlainTextf("%s: %s", markdown.Bold("Protocol"), sysConfig.System.WebGUI.Protocol)
	}

	// System Settings
	md.H3("System Settings")
	md.PlainTextf("%s: %s", markdown.Bold("DNS Allow Override"), formatIntBoolean(sysConfig.System.DNSAllowOverride))
	md.PlainTextf("%s: %d", markdown.Bold("Next UID"), sysConfig.System.NextUID)
	md.PlainTextf("%s: %d", markdown.Bold("Next GID"), sysConfig.System.NextGID)

	if sysConfig.System.TimeServers != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Time Servers"), sysConfig.System.TimeServers)
	}

	if sysConfig.System.DNSServer != "" {
		md.PlainTextf("%s: %s", markdown.Bold("DNS Server"), sysConfig.System.DNSServer)
	}

	// Hardware Offloading
	md.H3("Hardware Offloading")
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Disable NAT Reflection"),
		formatBoolean(sysConfig.System.DisableNATReflection),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Use Virtual Terminal"),
		formatIntBoolean(sysConfig.System.UseVirtualTerminal),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Disable Console Menu"),
		formatStructBoolean(sysConfig.System.DisableConsoleMenu),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Disable VLAN HW Filter"),
		formatIntBoolean(sysConfig.System.DisableVLANHWFilter),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Disable Checksum Offloading"),
		formatIntBoolean(sysConfig.System.DisableChecksumOffloading),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Disable Segmentation Offloading"),
		formatIntBoolean(sysConfig.System.DisableSegmentationOffloading),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Disable Large Receive Offloading"),
		formatIntBoolean(sysConfig.System.DisableLargeReceiveOffloading),
	)
	md.PlainTextf("%s: %s", markdown.Bold("IPv6 Allow"), formatBoolean(sysConfig.System.IPv6Allow))

	// Power Management
	md.H3("Power Management")
	md.PlainTextf("%s: %s", markdown.Bold("Powerd AC Mode"), getPowerModeDescription(sysConfig.System.PowerdACMode))
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Powerd Battery Mode"),
		getPowerModeDescription(sysConfig.System.PowerdBatteryMode),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Powerd Normal Mode"),
		getPowerModeDescription(sysConfig.System.PowerdNormalMode),
	)

	// System Features
	md.H3("System Features")
	md.PlainTextf("%s: %s", markdown.Bold("PF Share Forward"), formatIntBoolean(sysConfig.System.PfShareForward))
	md.PlainTextf("%s: %s", markdown.Bold("LB Use Sticky"), formatIntBoolean(sysConfig.System.LbUseSticky))
	md.PlainTextf("%s: %s", markdown.Bold("RRD Backup"), formatIntBooleanWithUnset(sysConfig.System.RrdBackup))
	md.PlainTextf("%s: %s", markdown.Bold("Netflow Backup"), formatIntBooleanWithUnset(sysConfig.System.NetflowBackup))

	// Bogons Configuration
	if sysConfig.System.Bogons.Interval != "" {
		md.H3("Bogons Configuration")
		md.PlainTextf("%s: %s", markdown.Bold("Interval"), sysConfig.System.Bogons.Interval)
	}

	// SSH Configuration
	if sysConfig.System.SSH.Group != "" {
		md.H3("SSH Configuration")
		md.PlainTextf("%s: %s", markdown.Bold("Group"), sysConfig.System.SSH.Group)
	}

	// Firmware Information
	if sysConfig.System.Firmware.Version != "" {
		md.H3("Firmware Information")
		md.PlainTextf("%s: %s", markdown.Bold("Version"), sysConfig.System.Firmware.Version)
	}

	// System Tunables
	if len(sysConfig.Sysctl) > 0 {
		md.H3("System Tunables")
		tableSet := b.BuildSysctlTable(sysConfig.Sysctl)
		md.Table(*tableSet)
	}

	// Users
	if len(sysConfig.System.User) > 0 {
		md.H3("System Users")
		tableSet := b.BuildUserTable(sysConfig.System.User)
		md.Table(*tableSet)
	}

	// Groups
	if len(sysConfig.System.Group) > 0 {
		md.H3("System Groups")
		tableSet := b.BuildGroupTable(sysConfig.System.Group)
		md.Table(*tableSet)
	}

	return md.String()
}

// BuildNetworkSection builds the network configuration section.
func (b *MarkdownBuilder) BuildNetworkSection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	netConfig := data.NetworkConfig()

	md.H2("Network Configuration")

	// Interfaces table
	md.H3("Interfaces")
	tableSet := b.BuildInterfaceTable(netConfig.Interfaces)
	md.Table(*tableSet)

	// Individual interface details
	for name, iface := range netConfig.Interfaces.Items {
		sectionName := strings.ToUpper(name[:1]) + strings.ToLower(name[1:]) + " Interface"
		md.H3(sectionName)
		buildInterfaceDetails(md, iface)
	}

	return md.String()
}

// buildInterfaceDetails builds interface configuration details.
func buildInterfaceDetails(md *markdown.Markdown, iface model.Interface) {
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

// BuildSecuritySection builds the security configuration section.
func (b *MarkdownBuilder) BuildSecuritySection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	secConfig := data.SecurityConfig()

	md.H2("Security Configuration")

	// NAT Configuration
	md.H3("NAT Configuration")

	if secConfig.Nat.Outbound.Mode != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Outbound NAT Mode"), secConfig.Nat.Outbound.Mode)
	}

	// NAT Summary
	natSummary := data.NATSummary()
	if natSummary.Mode != "" {
		md.H4("NAT Summary")
		md.PlainTextf("%s: %s", markdown.Bold("NAT Mode"), natSummary.Mode)
		md.PlainTextf("%s: %s", markdown.Bold("NAT Reflection"), formatBool(natSummary.ReflectionDisabled))
		md.PlainTextf("%s: %s", markdown.Bold("Port Forward State Sharing"), formatBool(natSummary.PfShareForward))
		md.PlainTextf("%s: %d", markdown.Bold("Outbound Rules"), len(natSummary.OutboundRules))

		if natSummary.ReflectionDisabled {
			md.PlainText(
				"**Security Note**: NAT reflection is properly disabled, preventing potential security issues where internal clients can access internal services via external IP addresses.",
			)
		} else {
			md.PlainText("**⚠️ Security Warning**: NAT reflection is enabled, which may allow internal clients to access internal services via external IP addresses. Consider disabling if not needed.")
		}
	}

	// Firewall Rules
	rules := data.FilterRules()
	if len(rules) > 0 {
		md.H3("Firewall Rules")
		tableSet := b.BuildFirewallRulesTable(rules)
		md.Table(*tableSet)
	}

	return md.String()
}

// BuildServicesSection builds the service configuration section.
func (b *MarkdownBuilder) BuildServicesSection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	svcConfig := data.ServiceConfig()

	md.H2("Service Configuration")

	// DHCP Server
	md.H3("DHCP Server")

	if lanDhcp, ok := svcConfig.Dhcpd.Get("lan"); ok && lanDhcp.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("LAN DHCP Enabled"), formatBoolean(lanDhcp.Enable))

		if lanDhcp.Range.From != "" && lanDhcp.Range.To != "" {
			md.PlainTextf("%s: %s - %s", markdown.Bold("LAN DHCP Range"), lanDhcp.Range.From, lanDhcp.Range.To)
		}
	}

	if wanDhcp, ok := svcConfig.Dhcpd.Get("wan"); ok && wanDhcp.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("WAN DHCP Enabled"), formatBoolean(wanDhcp.Enable))
	}

	// DNS Resolver (Unbound)
	md.H3("DNS Resolver (Unbound)")

	if svcConfig.Unbound.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Enabled"), formatBoolean(svcConfig.Unbound.Enable))
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

	return md.String()
}

// BuildFirewallRulesTable builds a table of firewall rules.
func (b *MarkdownBuilder) BuildFirewallRulesTable(rules []model.Rule) *markdown.TableSet {
	headers := []string{
		"#",
		"Interface",
		"Action",
		"IP Ver",
		"Proto",
		"Source",
		"Destination",
		"Target",
		"Source Port",
		"Enabled",
		"Description",
	}

	rows := make([][]string, 0, len(rules))
	for i, rule := range rules {
		source := rule.Source.Network
		if source == "" {
			source = destinationAny
		}

		dest := rule.Destination.Network
		if dest == "" {
			dest = destinationAny
		}

		interfaceLinks := formatInterfacesAsLinks(rule.Interface)

		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			interfaceLinks,
			rule.Type,
			rule.IPProtocol,
			rule.Protocol,
			source,
			dest,
			rule.Target,
			rule.SourcePort,
			formatBooleanInverted(rule.Disabled),
			rule.Descr,
		})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// BuildInterfaceTable builds a table of network interfaces.
func (b *MarkdownBuilder) BuildInterfaceTable(interfaces model.Interfaces) *markdown.TableSet {
	headers := []string{"Name", "Description", "IP Address", "CIDR", "Enabled"}

	rows := make([][]string, 0, len(interfaces.Items))
	for name, iface := range interfaces.Items {
		description := iface.Descr
		if description == "" {
			description = iface.If
		}

		cidr := ""
		if iface.Subnet != "" {
			cidr = "/" + iface.Subnet
		}

		rows = append(rows, []string{
			fmt.Sprintf("`%s`", name),
			fmt.Sprintf("`%s`", description),
			fmt.Sprintf("`%s`", iface.IPAddr),
			cidr,
			formatBoolean(iface.Enable),
		})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// BuildUserTable builds a table of system users.
func (b *MarkdownBuilder) BuildUserTable(users []model.User) *markdown.TableSet {
	headers := []string{"Name", "Description", "Group", "Scope"}

	rows := make([][]string, 0, len(users))
	for _, user := range users {
		rows = append(rows, []string{user.Name, user.Descr, user.Groupname, user.Scope})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// BuildGroupTable builds a table of system groups.
func (b *MarkdownBuilder) BuildGroupTable(groups []model.Group) *markdown.TableSet {
	headers := []string{"Name", "Description", "Scope"}

	rows := make([][]string, 0, len(groups))
	for _, group := range groups {
		rows = append(rows, []string{group.Name, group.Description, group.Scope})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// BuildSysctlTable builds a table of system tunables.
func (b *MarkdownBuilder) BuildSysctlTable(sysctl []model.SysctlItem) *markdown.TableSet {
	headers := []string{"Tunable", "Value", "Description"}

	rows := make([][]string, 0, len(sysctl))
	for _, item := range sysctl {
		rows = append(rows, []string{item.Tunable, item.Value, item.Descr})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// BuildStandardReport builds a standard markdown report.
func (b *MarkdownBuilder) BuildStandardReport(data *model.OpnSenseDocument) (string, error) {
	if data == nil {
		return "", ErrNilOpnSenseDocument
	}

	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	// Main title
	md.H1("OPNsense Configuration Summary")

	// System Information
	md.H2("System Information")
	md.PlainTextf("- **Hostname**: %s", data.System.Hostname)
	md.PlainTextf("- **Domain**: %s", data.System.Domain)
	md.PlainTextf("- **Platform**: OPNsense %s", data.System.Firmware.Version)
	md.PlainTextf("- **Generated On**: %s", b.generated.Format("2006-01-02 15:04:05"))
	md.PlainTextf("- **Parsed By**: opnDossier v%s", b.toolVersion)

	// Table of Contents
	md.H2("Table of Contents")
	md.PlainText("- [System Configuration](#system-configuration)")
	md.PlainText("- [Interfaces](#interfaces)")
	md.PlainText("- [Firewall Rules](#firewall-rules)")
	md.PlainText("- [NAT Configuration](#nat-configuration)")
	md.PlainText("- [DHCP Services](#dhcp-services)")
	md.PlainText("- [DNS Resolver](#dns-resolver)")
	md.PlainText("- [System Users](#system-users)")
	md.PlainText("- [Services & Daemons](#services--daemons)")
	md.PlainText("- [System Tunables](#system-tunables)")

	// Build sections
	md.PlainText(b.BuildSystemSection(data))
	md.PlainText(b.BuildNetworkSection(data))
	md.PlainText(b.BuildSecuritySection(data))
	md.PlainText(b.BuildServicesSection(data))

	// Add system users and tunables sections
	sysConfig := data.SystemConfig()

	if len(sysConfig.System.User) > 0 {
		md.H2("System Users")
		tableSet := b.BuildUserTable(sysConfig.System.User)
		md.Table(*tableSet)
	}

	if len(sysConfig.Sysctl) > 0 {
		md.H2("System Tunables")
		tableSet := b.BuildSysctlTable(sysConfig.Sysctl)
		md.Table(*tableSet)
	}

	return md.String(), nil
}

// BuildComprehensiveReport builds a comprehensive markdown report.
func (b *MarkdownBuilder) BuildComprehensiveReport(data *model.OpnSenseDocument) (string, error) {
	if data == nil {
		return "", ErrNilOpnSenseDocument
	}

	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	// Main title
	md.H1("OPNsense Configuration Summary")

	// System Information
	md.H2("System Information")
	md.PlainTextf("- **Hostname**: %s", data.System.Hostname)
	md.PlainTextf("- **Domain**: %s", data.System.Domain)
	md.PlainTextf("- **Platform**: OPNsense %s", data.System.Firmware.Version)
	md.PlainTextf("- **Generated On**: %s", b.generated.Format("2006-01-02 15:04:05"))
	md.PlainTextf("- **Parsed By**: opnDossier v%s", b.toolVersion)

	// Table of Contents
	md.H2("Table of Contents")
	md.PlainText("- [System Configuration](#system-configuration)")
	md.PlainText("- [Interfaces](#interfaces)")
	md.PlainText("- [Firewall Rules](#firewall-rules)")
	md.PlainText("- [NAT Configuration](#nat-configuration)")
	md.PlainText("- [DHCP Services](#dhcp-services)")
	md.PlainText("- [DNS Resolver](#dns-resolver)")
	md.PlainText("- [System Users](#system-users)")
	md.PlainText("- [System Groups](#system-groups)")
	md.PlainText("- [Services & Daemons](#services--daemons)")
	md.PlainText("- [System Tunables](#system-tunables)")

	// Build comprehensive sections
	md.PlainText(b.BuildSystemSection(data))
	md.PlainText(b.BuildNetworkSection(data))
	md.PlainText(b.BuildSecuritySection(data))
	md.PlainText(b.BuildServicesSection(data))

	return md.String(), nil
}

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

	// WAN Interface - the H3 creates an implicit anchor #wan-interface
	md.H3("WAN Interface")

	if wan, ok := netConfig.Interfaces.Wan(); ok {
		buildInterfaceDetails(md, wan)
	}

	// LAN Interface - the H3 creates an implicit anchor #lan-interface
	md.H3("LAN Interface")

	if lan, ok := netConfig.Interfaces.Lan(); ok {
		buildInterfaceDetails(md, lan)
	}

	// Add other interfaces dynamically if they exist
	for name, iface := range netConfig.Interfaces.Items {
		if name != "wan" && name != "lan" {
			// Create consistent section names for other interfaces
			// Use proper case conversion for interface names
			sectionName := strings.ToUpper(name[:1]) + strings.ToLower(name[1:]) + " Interface"
			md.H3(sectionName)
			buildInterfaceDetails(md, iface)
		}
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

		headers := []string{"Type", "Interface", "IP Ver", "Protocol", "Source", "Destination", "Description"}

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

			// Format interfaces as hyperlinks instead of plain text
			interfaceLinks := formatInterfacesAsLinks(rule.Interface)

			rows = append(rows, []string{
				rule.Type,
				interfaceLinks,
				rule.IPProtocol,
				rule.Protocol,
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
