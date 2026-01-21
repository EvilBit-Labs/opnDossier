// Package builder provides programmatic report building functionality for OPNsense configurations.
package builder

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/nao1215/markdown"
)

const destinationAny = "any"

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
	BuildOutboundNATTable(rules []model.NATRule) *markdown.TableSet
	BuildInboundNATTable(rules []model.InboundRule) *markdown.TableSet

	// Report generation
	BuildStandardReport(data *model.OpnSenseDocument) (string, error)
	BuildComprehensiveReport(data *model.OpnSenseDocument) (string, error)
}

// MarkdownBuilder implements the ReportBuilder interface with comprehensive
// programmatic markdown generation capabilities.
type MarkdownBuilder struct {
	config      *model.OpnSenseDocument
	logger      *log.Logger
	generated   time.Time
	toolVersion string
}

// NewMarkdownBuilder creates a new MarkdownBuilder instance.
func NewMarkdownBuilder() *MarkdownBuilder {
	logger, err := log.New(log.Config{Level: "info"})
	if err != nil {
		logger = &log.Logger{}
	}
	return &MarkdownBuilder{
		generated:   time.Now(),
		toolVersion: constants.Version,
		logger:      logger,
	}
}

// NewMarkdownBuilderWithOptions creates a new MarkdownBuilder instance with custom options.
func NewMarkdownBuilderWithOptions(config *model.OpnSenseDocument, _ Options, logger *log.Logger) *MarkdownBuilder {
	if logger == nil {
		var err error
		logger, err = log.New(log.Config{Level: "info"})
		if err != nil {
			logger = &log.Logger{}
		}
	}
	return &MarkdownBuilder{
		config:      config,
		logger:      logger,
		generated:   time.Now(),
		toolVersion: constants.Version,
	}
}

// BuildSystemSection builds the system configuration section.
func (b *MarkdownBuilder) BuildSystemSection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	sysConfig := data.SystemConfig()

	md.H2("System Configuration")

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

	if sysConfig.System.WebGUI.Protocol != "" {
		md.H3("Web GUI Configuration")
		md.PlainTextf("%s: %s", markdown.Bold("Protocol"), sysConfig.System.WebGUI.Protocol)
	}

	md.H3("System Settings")
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("DNS Allow Override"),
		formatters.FormatIntBoolean(sysConfig.System.DNSAllowOverride),
	)
	md.PlainTextf("%s: %d", markdown.Bold("Next UID"), sysConfig.System.NextUID)
	md.PlainTextf("%s: %d", markdown.Bold("Next GID"), sysConfig.System.NextGID)

	if sysConfig.System.TimeServers != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Time Servers"), sysConfig.System.TimeServers)
	}

	if sysConfig.System.DNSServer != "" {
		md.PlainTextf("%s: %s", markdown.Bold("DNS Server"), sysConfig.System.DNSServer)
	}

	md.H3("Hardware Offloading")
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Disable NAT Reflection"),
		formatters.FormatBoolean(sysConfig.System.DisableNATReflection),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Use Virtual Terminal"),
		formatters.FormatIntBoolean(sysConfig.System.UseVirtualTerminal),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Disable Console Menu"),
		formatters.FormatStructBoolean(sysConfig.System.DisableConsoleMenu),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Disable VLAN HW Filter"),
		formatters.FormatIntBoolean(sysConfig.System.DisableVLANHWFilter),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Disable Checksum Offloading"),
		formatters.FormatIntBoolean(sysConfig.System.DisableChecksumOffloading),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Disable Segmentation Offloading"),
		formatters.FormatIntBoolean(sysConfig.System.DisableSegmentationOffloading),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Disable Large Receive Offloading"),
		formatters.FormatIntBoolean(sysConfig.System.DisableLargeReceiveOffloading),
	)
	md.PlainTextf("%s: %s", markdown.Bold("IPv6 Allow"), formatters.FormatBoolean(sysConfig.System.IPv6Allow))

	md.H3("Power Management")
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Powerd AC Mode"),
		formatters.GetPowerModeDescriptionCompact(sysConfig.System.PowerdACMode),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Powerd Battery Mode"),
		formatters.GetPowerModeDescriptionCompact(sysConfig.System.PowerdBatteryMode),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Powerd Normal Mode"),
		formatters.GetPowerModeDescriptionCompact(sysConfig.System.PowerdNormalMode),
	)

	md.H3("System Features")
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("PF Share Forward"),
		formatters.FormatIntBoolean(sysConfig.System.PfShareForward),
	)
	md.PlainTextf("%s: %s", markdown.Bold("LB Use Sticky"), formatters.FormatIntBoolean(sysConfig.System.LbUseSticky))
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("RRD Backup"),
		formatters.FormatIntBooleanWithUnset(sysConfig.System.RrdBackup),
	)
	md.PlainTextf(
		"%s: %s",
		markdown.Bold("Netflow Backup"),
		formatters.FormatIntBooleanWithUnset(sysConfig.System.NetflowBackup),
	)

	if sysConfig.System.Bogons.Interval != "" {
		md.H3("Bogons Configuration")
		md.PlainTextf("%s: %s", markdown.Bold("Interval"), sysConfig.System.Bogons.Interval)
	}

	if sysConfig.System.SSH.Group != "" {
		md.H3("SSH Configuration")
		md.PlainTextf("%s: %s", markdown.Bold("Group"), sysConfig.System.SSH.Group)
	}

	if sysConfig.System.Firmware.Version != "" {
		md.H3("Firmware Information")
		md.PlainTextf("%s: %s", markdown.Bold("Version"), sysConfig.System.Firmware.Version)
	}

	if len(sysConfig.Sysctl) > 0 {
		md.H3("System Tunables")
		tableSet := b.BuildSysctlTable(sysConfig.Sysctl)
		md.Table(*tableSet)
	}

	if len(sysConfig.System.User) > 0 {
		md.H3("System Users")
		tableSet := b.BuildUserTable(sysConfig.System.User)
		md.Table(*tableSet)
	}

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

	md.H3("Interfaces")
	tableSet := b.BuildInterfaceTable(netConfig.Interfaces)
	md.Table(*tableSet)

	for name, iface := range netConfig.Interfaces.Items {
		sectionName := strings.ToUpper(name[:1]) + strings.ToLower(name[1:]) + " Interface"
		md.H3(sectionName)
		buildInterfaceDetails(md, iface)
	}

	return md.String()
}

// BuildSecuritySection builds the security configuration section.
func (b *MarkdownBuilder) BuildSecuritySection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	secConfig := data.SecurityConfig()

	md.H2("Security Configuration")

	md.H3("NAT Configuration")

	natSummary := data.NATSummary()
	if natSummary.Mode != "" || secConfig.Nat.Outbound.Mode != "" {
		md.H4("NAT Summary")
		mode := natSummary.Mode
		if mode == "" {
			mode = secConfig.Nat.Outbound.Mode
		}
		md.PlainTextf("%s: %s", markdown.Bold("NAT Mode"), mode)
		md.PlainTextf("%s: %s", markdown.Bold("NAT Reflection"), formatters.FormatBool(natSummary.ReflectionDisabled))
		md.PlainTextf(
			"%s: %s",
			markdown.Bold("Port Forward State Sharing"),
			formatters.FormatBool(natSummary.PfShareForward),
		)
		md.PlainTextf("%s: %d", markdown.Bold("Outbound Rules"), len(natSummary.OutboundRules))
		md.PlainTextf("%s: %d", markdown.Bold("Inbound Rules"), len(natSummary.InboundRules))

		if natSummary.ReflectionDisabled {
			md.PlainText(
				"**Security Note**: NAT reflection is properly disabled, preventing potential security issues where internal clients can access internal services via external IP addresses.",
			)
		} else {
			md.PlainText(
				"**⚠️ Security Warning**: NAT reflection is enabled, which may allow internal clients to access internal services via external IP addresses. Consider disabling if not needed.",
			)
		}
	}

	md.H4("Outbound NAT (Source Translation)")
	outboundTableSet := b.BuildOutboundNATTable(natSummary.OutboundRules)
	md.Table(*outboundTableSet)

	md.H4("Inbound NAT (Port Forwarding)")
	inboundTableSet := b.BuildInboundNATTable(natSummary.InboundRules)
	md.Table(*inboundTableSet)

	if len(natSummary.InboundRules) > 0 {
		md.PlainText(
			"**⚠️ Security Warning**: Inbound NAT rules (port forwarding) increase the attack surface by exposing internal services to external networks. Ensure these rules are necessary and properly secured.",
		)
	}

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

	md.H3("DHCP Server")

	if lanDhcp, ok := svcConfig.Dhcpd.Get("lan"); ok && lanDhcp.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("LAN DHCP Enabled"), formatters.FormatBoolean(lanDhcp.Enable))

		if lanDhcp.Range.From != "" && lanDhcp.Range.To != "" {
			md.PlainTextf("%s: %s - %s", markdown.Bold("LAN DHCP Range"), lanDhcp.Range.From, lanDhcp.Range.To)
		}
	}

	if wanDhcp, ok := svcConfig.Dhcpd.Get("wan"); ok && wanDhcp.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("WAN DHCP Enabled"), formatters.FormatBoolean(wanDhcp.Enable))
	}

	md.H3("DNS Resolver (Unbound)")

	if svcConfig.Unbound.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Enabled"), formatters.FormatBoolean(svcConfig.Unbound.Enable))
	}

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

	md.H3("NTP")

	if svcConfig.Ntpd.Prefer != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Preferred Server"), svcConfig.Ntpd.Prefer)
	}

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

		interfaceLinks := formatters.FormatInterfacesAsLinks(rule.Interface)

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
			formatters.FormatBooleanInverted(rule.Disabled),
			formatters.EscapeTableContent(rule.Descr),
		})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// BuildOutboundNATTable builds a table of outbound NAT rules (source translation/masquerading).
func (b *MarkdownBuilder) BuildOutboundNATTable(rules []model.NATRule) *markdown.TableSet {
	headers := []string{
		"#",
		"Direction",
		"Interface",
		"Source",
		"Destination",
		"Target",
		"Protocol",
		"Description",
		"Status",
	}

	rows := make([][]string, 0, len(rules))

	if len(rules) == 0 {
		rows = append(rows, []string{
			"-", "-", "-", "-", "-", "-", "-",
			"No outbound NAT rules configured",
			"-",
		})
	} else {
		for i, rule := range rules {
			source := rule.Source.Network
			if source == "" {
				source = destinationAny
			}

			dest := rule.Destination.Network
			if dest == "" && rule.Destination.Any != "" {
				dest = destinationAny
			}

			protocol := rule.Protocol
			if protocol == "" {
				protocol = "any"
			}

			target := rule.Target
			if target != "" {
				target = fmt.Sprintf("`%s`", target)
			}

			status := "**Active**"
			if rule.Disabled != "" {
				status = "**Disabled**"
			}

			interfaceLinks := formatters.FormatInterfacesAsLinks(rule.Interface)

			rows = append(rows, []string{
				strconv.Itoa(i + 1),
				"⬆️ Outbound",
				interfaceLinks,
				source,
				dest,
				target,
				protocol,
				formatters.EscapeTableContent(rule.Descr),
				status,
			})
		}
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// BuildInboundNATTable builds a table of inbound NAT rules (port forwarding/destination NAT).
func (b *MarkdownBuilder) BuildInboundNATTable(rules []model.InboundRule) *markdown.TableSet {
	headers := []string{
		"#",
		"Direction",
		"Interface",
		"External Port",
		"Target IP",
		"Target Port",
		"Protocol",
		"Description",
		"Priority",
		"Status",
	}

	rows := make([][]string, 0, len(rules))

	if len(rules) == 0 {
		rows = append(rows, []string{
			"-", "-", "-", "-", "-", "-", "-",
			"No inbound NAT rules configured",
			"-", "-",
		})
	} else {
		for i, rule := range rules {
			protocol := rule.Protocol
			if protocol == "" {
				protocol = "any"
			}

			targetIP := rule.InternalIP
			if targetIP != "" {
				targetIP = fmt.Sprintf("`%s`", targetIP)
			}

			status := "**Active**"
			if rule.Disabled != "" {
				status = "**Disabled**"
			}

			interfaceLinks := formatters.FormatInterfacesAsLinks(rule.Interface)

			rows = append(rows, []string{
				strconv.Itoa(i + 1),
				"⬇️ Inbound",
				interfaceLinks,
				rule.ExternalPort,
				targetIP,
				rule.InternalPort,
				protocol,
				formatters.EscapeTableContent(rule.Descr),
				strconv.Itoa(rule.Priority),
				status,
			})
		}
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
			fmt.Sprintf("`%s`", formatters.EscapeTableContent(description)),
			fmt.Sprintf("`%s`", iface.IPAddr),
			cidr,
			formatters.FormatBoolean(iface.Enable),
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
		rows = append(rows, []string{
			formatters.EscapeTableContent(user.Name),
			formatters.EscapeTableContent(user.Descr),
			formatters.EscapeTableContent(user.Groupname),
			formatters.EscapeTableContent(user.Scope),
		})
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
		rows = append(rows, []string{
			formatters.EscapeTableContent(group.Name),
			formatters.EscapeTableContent(group.Description),
			formatters.EscapeTableContent(group.Scope),
		})
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
		rows = append(rows, []string{
			formatters.EscapeTableContent(item.Tunable),
			formatters.EscapeTableContent(item.Value),
			formatters.EscapeTableContent(item.Descr),
		})
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

	md.H1("OPNsense Configuration Summary")

	md.H2("System Information")
	md.PlainTextf("- **Hostname**: %s", data.System.Hostname)
	md.PlainTextf("- **Domain**: %s", data.System.Domain)
	md.PlainTextf("- **Platform**: OPNsense %s", data.System.Firmware.Version)
	md.PlainTextf("- **Generated On**: %s", b.generated.Format("2006-01-02 15:04:05"))
	md.PlainTextf("- **Parsed By**: opnDossier v%s", b.toolVersion)

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

	md.PlainText(b.BuildSystemSection(data))
	md.PlainText(b.BuildNetworkSection(data))
	md.PlainText(b.BuildSecuritySection(data))
	md.PlainText(b.BuildServicesSection(data))

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

	md.H1("OPNsense Configuration Summary")

	md.H2("System Information")
	md.PlainTextf("- **Hostname**: %s", data.System.Hostname)
	md.PlainTextf("- **Domain**: %s", data.System.Domain)
	md.PlainTextf("- **Platform**: OPNsense %s", data.System.Firmware.Version)
	md.PlainTextf("- **Generated On**: %s", b.generated.Format("2006-01-02 15:04:05"))
	md.PlainTextf("- **Parsed By**: opnDossier v%s", b.toolVersion)

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

	md.PlainText(b.BuildSystemSection(data))
	md.PlainText(b.BuildNetworkSection(data))
	md.PlainText(b.BuildSecuritySection(data))
	md.PlainText(b.BuildServicesSection(data))

	return md.String(), nil
}

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
