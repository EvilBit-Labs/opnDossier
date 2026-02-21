// Package converter provides functionality to convert device configurations to markdown.
package converter

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/charmbracelet/glamour"
	"github.com/nao1215/markdown"
)

// Constants for common values.
const destinationAny = "any"

// Converter is the interface for converting device configurations to markdown.
type Converter interface {
	ToMarkdown(ctx context.Context, data *common.CommonDevice) (string, error)
}

// MarkdownConverter is a markdown converter for device configurations.
type MarkdownConverter struct{}

// NewMarkdownConverter creates and returns a new MarkdownConverter for converting device configuration data to markdown format.
func NewMarkdownConverter() *MarkdownConverter {
	return &MarkdownConverter{}
}

// ToMarkdown converts a device configuration to markdown.
func (c *MarkdownConverter) ToMarkdown(_ context.Context, data *common.CommonDevice) (string, error) {
	if data == nil {
		return "", ErrNilDevice
	}

	// Create markdown using github.com/nao1215/markdown for structured output
	var buf bytes.Buffer

	md := markdown.NewMarkdown(&buf)

	// Main title
	md.H1("OPNsense Configuration")

	// System Configuration
	c.buildSystemSection(md, data)

	// Network Configuration
	c.buildNetworkSection(md, data)

	// Security Configuration
	c.buildSecuritySection(md, data)

	// Service Configuration
	c.buildServiceSection(md, data)

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
func (c *MarkdownConverter) buildSystemSection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H2("System Configuration")

	c.buildBasicInfo(md, data)
	c.buildWebGUI(md, data)
	c.buildSysctl(md, data)
	c.buildUsers(md, data)
	c.buildGroups(md, data)
}

// buildBasicInfo builds the basic system information section.
func (c *MarkdownConverter) buildBasicInfo(md *markdown.Markdown, data *common.CommonDevice) {
	// Basic system information
	md.H3("Basic Information")
	md.PlainTextf("%s: %s", markdown.Bold("Hostname"), data.System.Hostname)
	md.PlainTextf("%s: %s", markdown.Bold("Domain"), data.System.Domain)

	if data.System.Timezone != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Timezone"), data.System.Timezone)
	}

	if data.System.Optimization != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Optimization"), data.System.Optimization)
	}
}

// buildWebGUI builds the WebGUI configuration section.
func (c *MarkdownConverter) buildWebGUI(md *markdown.Markdown, data *common.CommonDevice) {
	if data.System.WebGUI.Protocol != "" {
		md.H3("Web GUI")
		md.PlainTextf("%s: %s", markdown.Bold("Protocol"), data.System.WebGUI.Protocol)
	}
}

// buildSysctl builds the sysctl configuration as a table.
func (c *MarkdownConverter) buildSysctl(md *markdown.Markdown, data *common.CommonDevice) {
	if len(data.Sysctl) > 0 {
		md.H3("System Tuning")

		headers := []string{"Tunable", "Value", "Description"}

		rows := make([][]string, 0, len(data.Sysctl))
		for _, item := range data.Sysctl {
			rows = append(rows, []string{item.Tunable, item.Value, item.Description})
		}

		tableSet := markdown.TableSet{
			Header: headers,
			Rows:   rows,
		}
		md.Table(tableSet)
	}
}

// buildUsers builds the users configuration as a table.
func (c *MarkdownConverter) buildUsers(md *markdown.Markdown, data *common.CommonDevice) {
	if len(data.Users) > 0 {
		md.H3("Users")

		headers := []string{"Name", "Description", "Group", "Scope"}

		rows := make([][]string, 0, len(data.Users))
		for _, user := range data.Users {
			rows = append(rows, []string{user.Name, user.Description, user.GroupName, user.Scope})
		}

		tableSet := markdown.TableSet{
			Header: headers,
			Rows:   rows,
		}
		md.Table(tableSet)
	}
}

// buildGroups builds the groups configuration as a table.
func (c *MarkdownConverter) buildGroups(md *markdown.Markdown, data *common.CommonDevice) {
	if len(data.Groups) > 0 {
		md.H3("Groups")

		headers := []string{"Name", "Description", "Scope"}

		rows := make([][]string, 0, len(data.Groups))
		for _, group := range data.Groups {
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
func (c *MarkdownConverter) buildNetworkSection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H2("Network Configuration")

	for _, iface := range data.Interfaces {
		name := iface.Name
		if name == "" {
			name = "unnamed"
		}
		sectionName := strings.ToUpper(name[:1]) + strings.ToLower(name[1:]) + " Interface"
		md.H3(sectionName)
		buildInterfaceDetails(md, iface)
	}
}

// buildInterfaceDetails builds interface configuration details.
func buildInterfaceDetails(md *markdown.Markdown, iface common.Interface) {
	if iface.PhysicalIf != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Physical Interface"), iface.PhysicalIf)
	}

	md.PlainTextf("%s: %s", markdown.Bold("Enabled"), formatters.FormatBool(iface.Enabled))

	if iface.IPAddress != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv4 Address"), iface.IPAddress)
	}

	if iface.Subnet != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv4 Subnet"), iface.Subnet)
	}

	if iface.IPv6Address != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv6 Address"), iface.IPv6Address)
	}

	if iface.SubnetV6 != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv6 Subnet"), iface.SubnetV6)
	}

	if iface.Gateway != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Gateway"), iface.Gateway)
	}

	if iface.MTU != "" {
		md.PlainTextf("%s: %s", markdown.Bold("MTU"), iface.MTU)
	}

	md.PlainTextf("%s: %s", markdown.Bold("Block Private Networks"), formatters.FormatBool(iface.BlockPrivate))
	md.PlainTextf("%s: %s", markdown.Bold("Block Bogon Networks"), formatters.FormatBool(iface.BlockBogons))
}

// buildSecuritySection builds the security configuration section using helper methods.
func (c *MarkdownConverter) buildSecuritySection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H2("Security Configuration")

	// NAT Configuration
	md.H3("NAT Configuration")

	if data.NAT.OutboundMode != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Outbound NAT Mode"), data.NAT.OutboundMode)
	}

	// Firewall Rules
	if len(data.FirewallRules) > 0 {
		md.H3("Firewall Rules")

		headers := []string{"Type", "Interface", "IP Ver", "Protocol", "Source", "Destination", "Description"}

		rows := make([][]string, 0, len(data.FirewallRules))
		for _, rule := range data.FirewallRules {
			source := rule.Source.Address
			if source == "" {
				source = destinationAny
			}

			dest := rule.Destination.Address
			if dest == "" {
				dest = destinationAny
			}

			// Format interfaces as hyperlinks instead of plain text
			interfaceLinks := formatters.FormatInterfacesAsLinks(rule.Interfaces)

			rows = append(rows, []string{
				rule.Type,
				interfaceLinks,
				rule.IPProtocol,
				rule.Protocol,
				source,
				dest,
				rule.Description,
			})
		}

		tableSet := markdown.TableSet{
			Header: headers,
			Rows:   rows,
		}
		md.Table(tableSet)
	}

	// IDS/Suricata Configuration
	c.buildIDSSection(md, data)
}

// buildIDSSection builds the IDS/Suricata configuration section.
func (c *MarkdownConverter) buildIDSSection(md *markdown.Markdown, data *common.CommonDevice) {
	if data.IDS == nil || !data.IDS.Enabled {
		return
	}

	ids := data.IDS

	md.H3("Intrusion Detection System (IDS/Suricata)")

	md.PlainTextf("%s: %s", markdown.Bold("Status"), "Enabled")

	mode := "IDS"
	if ids.IPSMode {
		mode = "IPS"
	}
	md.PlainTextf("%s: %s", markdown.Bold("Mode"), mode)

	if ids.Detect.Profile != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Detection Profile"), ids.Detect.Profile)
	}

	if ids.MPMAlgo != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Pattern Matching Algorithm"), ids.MPMAlgo)
	}

	if len(ids.Interfaces) > 0 {
		md.PlainTextf("%s: %s", markdown.Bold("Monitored Interfaces"), strings.Join(ids.Interfaces, ", "))
	}

	if len(ids.HomeNetworks) > 0 {
		md.PlainTextf("%s: %s", markdown.Bold("Home Networks"), strings.Join(ids.HomeNetworks, ", "))
	}

	md.PlainTextf("%s: %s", markdown.Bold("Promiscuous Mode"), formatters.FormatBoolStatus(ids.Promiscuous))
	md.PlainTextf("%s: %s", markdown.Bold("Syslog Output"), formatters.FormatBoolStatus(ids.SyslogEnabled))
	md.PlainTextf("%s: %s", markdown.Bold("EVE Syslog Output"), formatters.FormatBoolStatus(ids.SyslogEveEnabled))

	if ids.LogPayload != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Log Payload"), ids.LogPayload)
	}

	if ids.AlertLogrotate != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Log Rotation"), ids.AlertLogrotate)
	}

	if ids.AlertSaveLogs != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Log Retention"), ids.AlertSaveLogs)
	}
}

// buildServiceSection builds the service configuration section using helper methods.
func (c *MarkdownConverter) buildServiceSection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H2("Service Configuration")

	// DHCP Server
	md.H3("DHCP Server")

	for _, scope := range data.DHCP {
		if scope.Enabled {
			label := strings.ToUpper(scope.Interface)
			md.PlainTextf("%s: %s", markdown.Bold(label+" DHCP Enabled"), formatters.FormatBool(scope.Enabled))

			if scope.Range.From != "" && scope.Range.To != "" {
				md.PlainTextf("%s: %s - %s", markdown.Bold(label+" DHCP Range"), scope.Range.From, scope.Range.To)
			}
		}
	}

	// DNS Resolver (Unbound)
	md.H3("DNS Resolver (Unbound)")

	if data.DNS.Unbound.Enabled {
		md.PlainTextf("%s: %s", markdown.Bold("Enabled"), formatters.FormatBool(data.DNS.Unbound.Enabled))
	}

	// SNMP
	md.H3("SNMP")

	if data.SNMP.SysLocation != "" {
		md.PlainTextf("%s: %s", markdown.Bold("System Location"), data.SNMP.SysLocation)
	}

	if data.SNMP.SysContact != "" {
		md.PlainTextf("%s: %s", markdown.Bold("System Contact"), data.SNMP.SysContact)
	}

	if data.SNMP.ROCommunity != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Read-Only Community"), data.SNMP.ROCommunity)
	}

	// NTP
	md.H3("NTP")

	if data.NTP.PreferredServer != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Preferred Server"), data.NTP.PreferredServer)
	}

	// Load Balancer
	if len(data.LoadBalancer.MonitorTypes) > 0 {
		md.H3("Load Balancer Monitors")

		headers := []string{"Name", "Type", "Description"}

		rows := make([][]string, 0, len(data.LoadBalancer.MonitorTypes))
		for _, monitor := range data.LoadBalancer.MonitorTypes {
			rows = append(rows, []string{monitor.Name, monitor.Type, monitor.Description})
		}

		tableSet := markdown.TableSet{
			Header: headers,
			Rows:   rows,
		}
		md.Table(tableSet)
	}
}
