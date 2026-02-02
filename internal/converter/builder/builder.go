// Package builder provides programmatic report building functionality for OPNsense configurations.
package builder

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
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
	// BuildSystemSection builds the system configuration section.
	BuildSystemSection(data *model.OpnSenseDocument) string
	// BuildNetworkSection builds the network configuration section.
	BuildNetworkSection(data *model.OpnSenseDocument) string
	// BuildSecuritySection builds the security configuration section.
	BuildSecuritySection(data *model.OpnSenseDocument) string
	// BuildServicesSection builds the services configuration section.
	BuildServicesSection(data *model.OpnSenseDocument) string

	// WriteFirewallRulesTable writes a firewall rules table and returns md for chaining.
	WriteFirewallRulesTable(md *markdown.Markdown, rules []model.Rule) *markdown.Markdown
	// WriteInterfaceTable writes an interfaces table and returns md for chaining.
	WriteInterfaceTable(md *markdown.Markdown, interfaces model.Interfaces) *markdown.Markdown
	// WriteUserTable writes a users table and returns md for chaining.
	WriteUserTable(md *markdown.Markdown, users []model.User) *markdown.Markdown
	// WriteGroupTable writes a groups table and returns md for chaining.
	WriteGroupTable(md *markdown.Markdown, groups []model.Group) *markdown.Markdown
	// WriteSysctlTable writes a sysctl tunables table and returns md for chaining.
	WriteSysctlTable(md *markdown.Markdown, sysctl []model.SysctlItem) *markdown.Markdown
	// WriteOutboundNATTable writes an outbound NAT rules table and returns md for chaining.
	WriteOutboundNATTable(md *markdown.Markdown, rules []model.NATRule) *markdown.Markdown
	// WriteInboundNATTable writes an inbound NAT/port forward rules table and returns md for chaining.
	WriteInboundNATTable(md *markdown.Markdown, rules []model.InboundRule) *markdown.Markdown
	// WriteVLANTable writes a VLAN configurations table and returns md for chaining.
	WriteVLANTable(md *markdown.Markdown, vlans []model.VLAN) *markdown.Markdown
	// WriteStaticRoutesTable writes a static routes table and returns md for chaining.
	WriteStaticRoutesTable(md *markdown.Markdown, routes []model.StaticRoute) *markdown.Markdown

	// BuildIPsecSection builds the IPsec VPN configuration section.
	BuildIPsecSection(data *model.OpnSenseDocument) string
	// BuildOpenVPNSection builds the OpenVPN configuration section.
	BuildOpenVPNSection(data *model.OpnSenseDocument) string
	// BuildHASection builds the High Availability and CARP configuration section.
	BuildHASection(data *model.OpnSenseDocument) string

	// BuildStandardReport generates a standard configuration report.
	BuildStandardReport(data *model.OpnSenseDocument) (string, error)
	// BuildComprehensiveReport generates a comprehensive configuration report.
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

// NewMarkdownBuilderWithConfig creates a new MarkdownBuilder instance with configuration.
func NewMarkdownBuilderWithConfig(config *model.OpnSenseDocument, logger *log.Logger) *MarkdownBuilder {
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

// writeSystemSection writes the system configuration section to the markdown instance.
func (b *MarkdownBuilder) writeSystemSection(md *markdown.Markdown, data *model.OpnSenseDocument) {
	sysConfig := data.SystemConfig()

	md.H2("System Configuration").
		H3("Basic Information").
		PlainTextf("%s: %s", markdown.Bold("Hostname"), sysConfig.System.Hostname).LF().
		PlainTextf("%s: %s", markdown.Bold("Domain"), sysConfig.System.Domain).LF()

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

	md.H3("System Settings").
		PlainTextf(
			"%s: %s",
			markdown.Bold("DNS Allow Override"),
			formatters.FormatIntBoolean(sysConfig.System.DNSAllowOverride),
		).LF().
		PlainTextf("%s: %d", markdown.Bold("Next UID"), sysConfig.System.NextUID).LF().
		PlainTextf("%s: %d", markdown.Bold("Next GID"), sysConfig.System.NextGID).LF()

	if sysConfig.System.TimeServers != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Time Servers"), sysConfig.System.TimeServers)
	}

	if sysConfig.System.DNSServer != "" {
		md.PlainTextf("%s: %s", markdown.Bold("DNS Server"), sysConfig.System.DNSServer)
	}

	md.H3("Hardware Offloading").
		PlainTextf(
			"%s: %s",
			markdown.Bold("Disable NAT Reflection"),
			formatters.FormatBoolean(sysConfig.System.DisableNATReflection),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Use Virtual Terminal"),
			formatters.FormatIntBoolean(sysConfig.System.UseVirtualTerminal),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Disable Console Menu"),
			formatters.FormatStructBoolean(sysConfig.System.DisableConsoleMenu),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Disable VLAN HW Filter"),
			formatters.FormatIntBoolean(sysConfig.System.DisableVLANHWFilter),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Disable Checksum Offloading"),
			formatters.FormatIntBoolean(sysConfig.System.DisableChecksumOffloading),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Disable Segmentation Offloading"),
			formatters.FormatIntBoolean(sysConfig.System.DisableSegmentationOffloading),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Disable Large Receive Offloading"),
			formatters.FormatIntBoolean(sysConfig.System.DisableLargeReceiveOffloading),
		).LF().
		PlainTextf("%s: %s", markdown.Bold("IPv6 Allow"), formatters.FormatBoolean(sysConfig.System.IPv6Allow)).LF()

	md.H3("Power Management").
		PlainTextf(
			"%s: %s",
			markdown.Bold("Powerd AC Mode"),
			formatters.GetPowerModeDescriptionCompact(sysConfig.System.PowerdACMode),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Powerd Battery Mode"),
			formatters.GetPowerModeDescriptionCompact(sysConfig.System.PowerdBatteryMode),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Powerd Normal Mode"),
			formatters.GetPowerModeDescriptionCompact(sysConfig.System.PowerdNormalMode),
		).LF()

	md.H3("System Features").
		PlainTextf(
			"%s: %s",
			markdown.Bold("PF Share Forward"),
			formatters.FormatIntBoolean(sysConfig.System.PfShareForward),
		).LF().
		PlainTextf("%s: %s", markdown.Bold("LB Use Sticky"), formatters.FormatIntBoolean(sysConfig.System.LbUseSticky)).
		LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("RRD Backup"),
			formatters.FormatIntBooleanWithUnset(sysConfig.System.RrdBackup),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Netflow Backup"),
			formatters.FormatIntBooleanWithUnset(sysConfig.System.NetflowBackup),
		)

	if sysConfig.System.Bogons.Interval != "" {
		md.H3("Bogons Configuration").
			PlainTextf("%s: %s", markdown.Bold("Interval"), sysConfig.System.Bogons.Interval)
	}

	if sysConfig.System.SSH.Group != "" {
		md.H3("SSH Configuration").
			PlainTextf("%s: %s", markdown.Bold("Group"), sysConfig.System.SSH.Group)
	}

	if sysConfig.System.Firmware.Version != "" {
		md.H3("Firmware Information").
			PlainTextf("%s: %s", markdown.Bold("Version"), sysConfig.System.Firmware.Version)
	}

	if len(sysConfig.System.User) > 0 {
		b.WriteUserTable(md.H3("System Users"), sysConfig.System.User)
	}

	if len(sysConfig.System.Group) > 0 {
		b.WriteGroupTable(md.H3("System Groups"), sysConfig.System.Group)
	}
}

// BuildSystemSection builds the system configuration section.
func (b *MarkdownBuilder) BuildSystemSection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeSystemSection(md, data)
	return md.String()
}

// writeNetworkSection writes the network configuration section to the markdown instance.
func (b *MarkdownBuilder) writeNetworkSection(md *markdown.Markdown, data *model.OpnSenseDocument) {
	netConfig := data.NetworkConfig()

	b.WriteInterfaceTable(
		md.H2("Network Configuration").H3("Interfaces"),
		netConfig.Interfaces,
	)

	for name, iface := range netConfig.Interfaces.Items {
		sectionName := strings.ToUpper(name[:1]) + strings.ToLower(name[1:]) + " Interface"
		md.H3(sectionName)
		buildInterfaceDetails(md, iface)
	}
}

// BuildNetworkSection builds the network configuration section.
func (b *MarkdownBuilder) BuildNetworkSection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeNetworkSection(md, data)
	return md.String()
}

// writeSecuritySection writes the security configuration section to the markdown instance.
func (b *MarkdownBuilder) writeSecuritySection(md *markdown.Markdown, data *model.OpnSenseDocument) {
	secConfig := data.SecurityConfig()

	md.H2("Security Configuration").
		H3("NAT Configuration")

	natSummary := data.NATSummary()
	if natSummary.Mode != "" || secConfig.Nat.Outbound.Mode != "" {
		md.H4("NAT Summary")
		mode := natSummary.Mode
		if mode == "" {
			mode = secConfig.Nat.Outbound.Mode
		}
		md.PlainTextf("%s: %s", markdown.Bold("NAT Mode"), mode).LF().
			PlainTextf("%s: %s", markdown.Bold("NAT Reflection"), formatters.FormatBool(natSummary.ReflectionDisabled)).
			LF().
			PlainTextf(
				"%s: %s",
				markdown.Bold("Port Forward State Sharing"),
				formatters.FormatBool(natSummary.PfShareForward),
			).LF().
			PlainTextf("%s: %d", markdown.Bold("Outbound Rules"), len(natSummary.OutboundRules)).LF().
			PlainTextf("%s: %d", markdown.Bold("Inbound Rules"), len(natSummary.InboundRules))

		if natSummary.ReflectionDisabled {
			md.Note(
				"NAT reflection is properly disabled, preventing potential security issues where internal clients can access internal services via external IP addresses.",
			)
		} else {
			md.Warning(
				"NAT reflection is enabled, which may allow internal clients to access internal services via external IP addresses. Consider disabling if not needed.",
			)
		}
	}

	b.WriteOutboundNATTable(md.H4("Outbound NAT (Source Translation)"), natSummary.OutboundRules)
	b.WriteInboundNATTable(md.H4("Inbound NAT (Port Forwarding)"), natSummary.InboundRules)

	if len(natSummary.InboundRules) > 0 {
		md.Warning(
			"Inbound NAT rules (port forwarding) increase the attack surface by exposing internal services to external networks. Ensure these rules are necessary and properly secured.",
		)
	}

	rules := data.FilterRules()
	if len(rules) > 0 {
		b.WriteFirewallRulesTable(md.H3("Firewall Rules"), rules)
	}
}

// BuildSecuritySection builds the security configuration section.
func (b *MarkdownBuilder) BuildSecuritySection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeSecuritySection(md, data)
	return md.String()
}

// writeServicesSection writes the service configuration section to the markdown instance.
func (b *MarkdownBuilder) writeServicesSection(md *markdown.Markdown, data *model.OpnSenseDocument) {
	svcConfig := data.ServiceConfig()

	md.H2("Service Configuration").
		H3("DHCP Server")

	if lanDhcp, ok := svcConfig.Dhcpd.Get("lan"); ok && lanDhcp.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("LAN DHCP Enabled"), formatters.FormatBoolean(lanDhcp.Enable)).LF()
		if lanDhcp.Range.From != "" && lanDhcp.Range.To != "" {
			md.PlainTextf("%s: %s - %s", markdown.Bold("LAN DHCP Range"), lanDhcp.Range.From, lanDhcp.Range.To).LF()
		}
	}

	if wanDhcp, ok := svcConfig.Dhcpd.Get("wan"); ok && wanDhcp.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("WAN DHCP Enabled"), formatters.FormatBoolean(wanDhcp.Enable)).LF()
	}

	md.H3("DNS Resolver (Unbound)")
	if svcConfig.Unbound.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Enabled"), formatters.FormatBoolean(svcConfig.Unbound.Enable)).LF()
	}

	md.H3("SNMP")
	if svcConfig.Snmpd.SysLocation != "" {
		md.PlainTextf("%s: %s", markdown.Bold("System Location"), svcConfig.Snmpd.SysLocation).LF()
	}
	if svcConfig.Snmpd.SysContact != "" {
		md.PlainTextf("%s: %s", markdown.Bold("System Contact"), svcConfig.Snmpd.SysContact).LF()
	}
	if svcConfig.Snmpd.ROCommunity != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Read-Only Community"), svcConfig.Snmpd.ROCommunity).LF()
	}

	md.H3("NTP")
	if svcConfig.Ntpd.Prefer != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Preferred Server"), svcConfig.Ntpd.Prefer).LF()
	}

	if len(svcConfig.LoadBalancer.MonitorType) > 0 {
		rows := make([][]string, 0, len(svcConfig.LoadBalancer.MonitorType))
		for _, monitor := range svcConfig.LoadBalancer.MonitorType {
			rows = append(rows, []string{monitor.Name, monitor.Type, monitor.Descr})
		}
		md.H3("Load Balancer Monitors").
			Table(markdown.TableSet{
				Header: []string{"Name", "Type", "Description"},
				Rows:   rows,
			})
	}
}

// BuildServicesSection builds the service configuration section.
func (b *MarkdownBuilder) BuildServicesSection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeServicesSection(md, data)
	return md.String()
}

// WriteFirewallRulesTable writes a firewall rules table and returns md for chaining.
func (b *MarkdownBuilder) WriteFirewallRulesTable(md *markdown.Markdown, rules []model.Rule) *markdown.Markdown {
	return md.Table(*BuildFirewallRulesTableSet(rules))
}

// BuildFirewallRulesTableSet builds the table data for firewall rules.
func BuildFirewallRulesTableSet(rules []model.Rule) *markdown.TableSet {
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

// WriteOutboundNATTable writes an outbound NAT rules table and returns md for chaining.
func (b *MarkdownBuilder) WriteOutboundNATTable(md *markdown.Markdown, rules []model.NATRule) *markdown.Markdown {
	return md.Table(*BuildOutboundNATTableSet(rules))
}

// BuildOutboundNATTableSet builds the table data for outbound NAT rules.
func BuildOutboundNATTableSet(rules []model.NATRule) *markdown.TableSet {
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

// WriteInboundNATTable writes an inbound NAT rules table and returns md for chaining.
func (b *MarkdownBuilder) WriteInboundNATTable(md *markdown.Markdown, rules []model.InboundRule) *markdown.Markdown {
	return md.Table(*BuildInboundNATTableSet(rules))
}

// BuildInboundNATTableSet builds the table data for inbound NAT rules.
func BuildInboundNATTableSet(rules []model.InboundRule) *markdown.TableSet {
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

// WriteInterfaceTable writes an interfaces table and returns md for chaining.
func (b *MarkdownBuilder) WriteInterfaceTable(md *markdown.Markdown, interfaces model.Interfaces) *markdown.Markdown {
	return md.Table(*BuildInterfaceTableSet(interfaces))
}

// BuildInterfaceTableSet builds the table data for network interfaces.
func BuildInterfaceTableSet(interfaces model.Interfaces) *markdown.TableSet {
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

// WriteUserTable writes a users table and returns md for chaining.
func (b *MarkdownBuilder) WriteUserTable(md *markdown.Markdown, users []model.User) *markdown.Markdown {
	return md.Table(*BuildUserTableSet(users))
}

// BuildUserTableSet builds the table data for system users.
func BuildUserTableSet(users []model.User) *markdown.TableSet {
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

// WriteGroupTable writes a groups table and returns md for chaining.
func (b *MarkdownBuilder) WriteGroupTable(md *markdown.Markdown, groups []model.Group) *markdown.Markdown {
	return md.Table(*BuildGroupTableSet(groups))
}

// BuildGroupTableSet builds the table data for system groups.
func BuildGroupTableSet(groups []model.Group) *markdown.TableSet {
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

// WriteSysctlTable writes a sysctl tunables table and returns md for chaining.
func (b *MarkdownBuilder) WriteSysctlTable(md *markdown.Markdown, sysctl []model.SysctlItem) *markdown.Markdown {
	return md.Table(*BuildSysctlTableSet(sysctl))
}

// BuildSysctlTableSet builds the table data for system tunables.
func BuildSysctlTableSet(sysctl []model.SysctlItem) *markdown.TableSet {
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
	md := markdown.NewMarkdown(&buf).
		H1("OPNsense Configuration Summary").
		H2("System Information").
		BulletList(
			markdown.Bold("Hostname")+": "+data.System.Hostname,
			markdown.Bold("Domain")+": "+data.System.Domain,
			markdown.Bold("Platform")+": OPNsense "+data.System.Firmware.Version,
			markdown.Bold("Generated On")+": "+b.generated.Format(time.RFC3339),
			markdown.Bold("Parsed By")+": opnDossier v"+b.toolVersion,
		).
		H2("Table of Contents").
		BulletList(
			markdown.Link("System Configuration", "#system-configuration"),
			markdown.Link("Interfaces", "#interfaces"),
			markdown.Link("Firewall Rules", "#firewall-rules"),
			markdown.Link("NAT Configuration", "#nat-configuration"),
			markdown.Link("DHCP Services", "#dhcp-services"),
			markdown.Link("DNS Resolver", "#dns-resolver"),
			markdown.Link("System Users", "#system-users"),
			markdown.Link("Services & Daemons", "#services--daemons"),
			markdown.Link("System Tunables", "#system-tunables"),
		)

	b.writeSystemSection(md, data)
	b.writeNetworkSection(md, data)
	b.writeSecuritySection(md, data)
	b.writeServicesSection(md, data)

	sysConfig := data.SystemConfig()
	if len(sysConfig.Sysctl) > 0 {
		b.WriteSysctlTable(md.H2("System Tunables"), sysConfig.Sysctl)
	}

	return md.String(), nil
}

// BuildComprehensiveReport builds a comprehensive markdown report.
func (b *MarkdownBuilder) BuildComprehensiveReport(data *model.OpnSenseDocument) (string, error) {
	if data == nil {
		return "", ErrNilOpnSenseDocument
	}

	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf).
		H1("OPNsense Configuration Summary").
		H2("System Information").
		BulletList(
			markdown.Bold("Hostname")+": "+data.System.Hostname,
			markdown.Bold("Domain")+": "+data.System.Domain,
			markdown.Bold("Platform")+": OPNsense "+data.System.Firmware.Version,
			markdown.Bold("Generated On")+": "+b.generated.Format(time.RFC3339),
			markdown.Bold("Parsed By")+": opnDossier v"+b.toolVersion,
		).
		H2("Table of Contents").
		BulletList(
			markdown.Link("System Configuration", "#system-configuration"),
			markdown.Link("Interfaces", "#interfaces"),
			markdown.Link("VLANs", "#vlan-configuration"),
			markdown.Link("Static Routes", "#static-routes"),
			markdown.Link("Firewall Rules", "#firewall-rules"),
			markdown.Link("NAT Configuration", "#nat-configuration"),
			markdown.Link("IPsec VPN", "#ipsec-vpn-configuration"),
			markdown.Link("OpenVPN", "#openvpn-configuration"),
			markdown.Link("High Availability", "#high-availability--carp"),
			markdown.Link("DHCP Services", "#dhcp-services"),
			markdown.Link("DNS Resolver", "#dns-resolver"),
			markdown.Link("System Users", "#system-users"),
			markdown.Link("System Groups", "#system-groups"),
			markdown.Link("Services & Daemons", "#services--daemons"),
			markdown.Link("System Tunables", "#system-tunables"),
		)

	b.writeSystemSection(md, data)
	b.writeNetworkSection(md, data)
	b.writeVLANSection(md, data)
	b.writeStaticRoutesSection(md, data)
	b.writeSecuritySection(md, data)
	b.writeIPsecSection(md, data)
	b.writeOpenVPNSection(md, data)
	b.writeHASection(md, data)
	b.writeServicesSection(md, data)

	sysConfig := data.SystemConfig()
	if len(sysConfig.Sysctl) > 0 {
		b.WriteSysctlTable(md.H2("System Tunables"), sysConfig.Sysctl)
	}

	return md.String(), nil
}

func buildInterfaceDetails(md *markdown.Markdown, iface model.Interface) {
	// Build a list of interface properties that are set
	if iface.If != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Physical Interface"), iface.If).LF()
	}
	if iface.Enable != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Enabled"), iface.Enable).LF()
	}
	if iface.IPAddr != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv4 Address"), iface.IPAddr).LF()
	}
	if iface.Subnet != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv4 Subnet"), iface.Subnet).LF()
	}
	if iface.IPAddrv6 != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv6 Address"), iface.IPAddrv6).LF()
	}
	if iface.Subnetv6 != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv6 Subnet"), iface.Subnetv6).LF()
	}
	if iface.Gateway != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Gateway"), iface.Gateway).LF()
	}
	if iface.MTU != "" {
		md.PlainTextf("%s: %s", markdown.Bold("MTU"), iface.MTU).LF()
	}
	if iface.BlockPriv != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Block Private Networks"), iface.BlockPriv).LF()
	}
	if iface.BlockBogons != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Block Bogon Networks"), iface.BlockBogons)
	}
}

// WriteVLANTable writes a VLAN configurations table and returns md for chaining.
func (b *MarkdownBuilder) WriteVLANTable(md *markdown.Markdown, vlans []model.VLAN) *markdown.Markdown {
	return md.Table(*BuildVLANTableSet(vlans))
}

// BuildVLANTableSet builds the table data for VLAN configurations.
func BuildVLANTableSet(vlans []model.VLAN) *markdown.TableSet {
	headers := []string{
		"VLAN Interface",
		"Physical Interface",
		"VLAN Tag",
		"Description",
		"Created",
		"Updated",
	}

	rows := make([][]string, 0, len(vlans))

	if len(vlans) == 0 {
		rows = append(rows, []string{
			"-", "-", "-", "No VLANs configured", "-", "-",
		})
	} else {
		for _, vlan := range vlans {
			rows = append(rows, []string{
				formatters.EscapeTableContent(vlan.Vlanif),
				formatters.EscapeTableContent(vlan.If),
				vlan.Tag,
				formatters.EscapeTableContent(vlan.Descr),
				vlan.Created,
				vlan.Updated,
			})
		}
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// WriteStaticRoutesTable writes a static routes table and returns md for chaining.
func (b *MarkdownBuilder) WriteStaticRoutesTable(md *markdown.Markdown, routes []model.StaticRoute) *markdown.Markdown {
	return md.Table(*BuildStaticRoutesTableSet(routes))
}

// BuildStaticRoutesTableSet builds the table data for static routes.
func BuildStaticRoutesTableSet(routes []model.StaticRoute) *markdown.TableSet {
	headers := []string{
		"Destination Network",
		"Gateway",
		"Description",
		"Status",
		"Created",
		"Updated",
	}

	rows := make([][]string, 0, len(routes))

	if len(routes) == 0 {
		rows = append(rows, []string{
			"-", "-", "No static routes configured", "-", "-", "-",
		})
	} else {
		for _, route := range routes {
			status := "**Enabled**"
			if route.Disabled {
				status = "Disabled"
			}

			rows = append(rows, []string{
				formatters.EscapeTableContent(route.Network),
				formatters.EscapeTableContent(route.Gateway),
				formatters.EscapeTableContent(route.Descr),
				status,
				route.Created,
				route.Updated,
			})
		}
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// WriteDHCPSummaryTable writes a DHCP scope summary table and returns md for chaining.
func (b *MarkdownBuilder) WriteDHCPSummaryTable(md *markdown.Markdown, dhcpd model.Dhcpd) *markdown.Markdown {
	return md.Table(*BuildDHCPSummaryTableSet(dhcpd))
}

// BuildDHCPSummaryTableSet builds the table data for DHCP scope summary.
func BuildDHCPSummaryTableSet(dhcpd model.Dhcpd) *markdown.TableSet {
	headers := []string{
		"Interface",
		"Enabled",
		"Gateway",
		"Range Start",
		"Range End",
		"DNS",
		"WINS",
		"NTP",
		"DDNS Algorithm",
	}

	rows := make([][]string, 0, len(dhcpd.Items))

	if len(dhcpd.Items) == 0 {
		rows = append(rows, []string{
			"-", "-", "-", "-", "-", "-", "-", "-",
			"No DHCP scopes configured",
		})
	} else {
		// Use sorted keys for deterministic ordering
		for _, ifaceName := range slices.Sorted(maps.Keys(dhcpd.Items)) {
			iface := dhcpd.Items[ifaceName]
			rows = append(rows, []string{
				formatters.EscapeTableContent(ifaceName),
				formatters.FormatBoolean(iface.Enable),
				formatters.EscapeTableContent(iface.Gateway),
				formatters.EscapeTableContent(iface.Range.From),
				formatters.EscapeTableContent(iface.Range.To),
				formatters.EscapeTableContent(iface.Dnsserver),
				formatters.EscapeTableContent(iface.Winsserver),
				formatters.EscapeTableContent(iface.Ntpserver),
				formatters.EscapeTableContent(iface.DdnsDomainAlgorithm),
			})
		}
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// WriteDHCPStaticLeasesTable writes a static DHCP leases table and returns md for chaining.
func (b *MarkdownBuilder) WriteDHCPStaticLeasesTable(
	md *markdown.Markdown,
	leases []model.DHCPStaticLease,
) *markdown.Markdown {
	return md.Table(*BuildDHCPStaticLeasesTableSet(leases))
}

// BuildDHCPStaticLeasesTableSet builds the table data for static DHCP leases.
func BuildDHCPStaticLeasesTableSet(leases []model.DHCPStaticLease) *markdown.TableSet {
	headers := []string{
		"Hostname",
		"MAC",
		"IP",
		"CID",
		"Filename",
		"Rootpath",
		"Default Lease",
		"Max Lease",
		"Description",
	}

	rows := make([][]string, 0, len(leases))

	if len(leases) == 0 {
		rows = append(rows, []string{
			"-", "-", "-", "-", "-", "-", "-", "-",
			"No static leases configured",
		})
	} else {
		for _, lease := range leases {
			rows = append(rows, []string{
				formatters.EscapeTableContent(lease.Hostname),
				formatters.EscapeTableContent(lease.Mac),
				formatters.EscapeTableContent(lease.IPAddr),
				formatters.EscapeTableContent(lease.Cid),
				formatters.EscapeTableContent(lease.Filename),
				formatters.EscapeTableContent(lease.Rootpath),
				FormatLeaseTime(lease.Defaultleasetime),
				FormatLeaseTime(lease.Maxleasetime),
				formatters.EscapeTableContent(lease.Descr),
			})
		}
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// BuildIPsecSection builds the IPsec VPN configuration section.
// writeIPsecSection writes the IPsec VPN configuration section to the markdown instance.
func (b *MarkdownBuilder) writeIPsecSection(md *markdown.Markdown, data *model.OpnSenseDocument) {
	md.H3("IPsec VPN Configuration")

	ipsec := data.OPNsense.IPsec
	if ipsec == nil {
		md.PlainText(markdown.Italic("No IPsec configuration present"))
		return
	}

	// General Configuration
	md.H4("General Configuration").
		Table(markdown.TableSet{
			Header: []string{"Setting", "Value"},
			Rows: [][]string{
				{"**Enabled**", formatters.FormatBoolean(ipsec.General.Enabled)},
				{"**Prefer Old SA**", formatters.FormatBoolean(ipsec.General.PreferredOldsa)},
				{"**Disable VPN Rules**", formatters.FormatBoolean(ipsec.General.Disablevpnrules)},
				{"**Passthrough Networks**", formatters.EscapeTableContent(ipsec.General.PassthroughNetworks)},
			},
		})

	// Charon IKE Daemon Configuration
	md.H4("Charon IKE Daemon Configuration").
		Table(markdown.TableSet{
			Header: []string{"Parameter", "Value"},
			Rows: [][]string{
				{"**Threads**", ipsec.Charon.Threads},
				{"**IKE SA Table Size**", ipsec.Charon.IkesaTableSize},
				{"**Max IKEv1 Exchanges**", ipsec.Charon.MaxIkev1Exchanges},
				{"**Retransmit Tries**", ipsec.Charon.RetransmitTries},
				{"**Retransmit Timeout**", formatters.FormatWithSuffix(ipsec.Charon.RetransmitTimeout, "s")},
				{"**Make Before Break**", formatters.FormatBoolean(ipsec.Charon.MakeBeforeBreak)},
			},
		})

	md.Note("Phase 1/Phase 2 tunnel configurations require additional parser implementation")
}

// BuildIPsecSection builds the IPsec VPN configuration section.
func (b *MarkdownBuilder) BuildIPsecSection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeIPsecSection(md, data)
	return md.String()
}

// writeOpenVPNSection writes the OpenVPN configuration section to the markdown instance.
func (b *MarkdownBuilder) writeOpenVPNSection(md *markdown.Markdown, data *model.OpnSenseDocument) {
	md.H3("OpenVPN Configuration")

	openvpn := data.OpenVPN

	// OpenVPN Servers
	if len(openvpn.Servers) == 0 {
		md.H4("OpenVPN Servers").
			PlainText(markdown.Italic("No OpenVPN servers configured"))
	} else {
		serverRows := make([][]string, 0, len(openvpn.Servers))
		for _, server := range openvpn.Servers {
			serverRows = append(serverRows, []string{
				formatters.EscapeTableContent(server.Description),
				server.Mode,
				server.Protocol,
				server.Interface,
				server.Local_port,
				formatters.EscapeTableContent(server.Tunnel_network),
				formatters.EscapeTableContent(server.Remote_network),
				formatters.EscapeTableContent(server.Cert_ref),
			})
		}
		md.H4("OpenVPN Servers").
			Table(markdown.TableSet{
				Header: []string{
					"Description",
					"Mode",
					"Protocol",
					"Interface",
					"Port",
					"Tunnel Network",
					"Remote Network",
					"Certificate",
				},
				Rows: serverRows,
			})
	}

	// OpenVPN Clients
	if len(openvpn.Clients) == 0 {
		md.H4("OpenVPN Clients").
			PlainText(markdown.Italic("No OpenVPN clients configured"))
	} else {
		clientRows := make([][]string, 0, len(openvpn.Clients))
		for _, client := range openvpn.Clients {
			clientRows = append(clientRows, []string{
				formatters.EscapeTableContent(client.Description),
				formatters.EscapeTableContent(client.Server_addr),
				client.Server_port,
				client.Mode,
				client.Protocol,
				formatters.EscapeTableContent(client.Cert_ref),
			})
		}
		md.H4("OpenVPN Clients").
			Table(markdown.TableSet{
				Header: []string{
					"Description",
					"Server Address",
					"Port",
					"Mode",
					"Protocol",
					"Certificate",
				},
				Rows: clientRows,
			})
	}

	// Client-Specific Overrides (CSC)
	if len(openvpn.CSC) == 0 {
		md.H4("Client-Specific Overrides").
			PlainText(markdown.Italic("No client-specific overrides configured"))
	} else {
		cscRows := make([][]string, 0, len(openvpn.CSC))
		for _, csc := range openvpn.CSC {
			cscRows = append(cscRows, []string{
				formatters.EscapeTableContent(csc.Common_name),
				formatters.EscapeTableContent(csc.Tunnel_network),
				formatters.EscapeTableContent(csc.Local_network),
				formatters.EscapeTableContent(csc.Remote_network),
				formatters.EscapeTableContent(csc.DNS_domain),
			})
		}
		md.H4("Client-Specific Overrides").
			Table(markdown.TableSet{
				Header: []string{
					"Common Name",
					"Tunnel Network",
					"Local Network",
					"Remote Network",
					"DNS Domain",
				},
				Rows: cscRows,
			})
	}
}

// BuildOpenVPNSection builds the OpenVPN configuration section with servers, clients, and CSC.
func (b *MarkdownBuilder) BuildOpenVPNSection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeOpenVPNSection(md, data)
	return md.String()
}

// writeVLANSection writes the VLAN configuration section to the markdown instance.
func (b *MarkdownBuilder) writeVLANSection(md *markdown.Markdown, data *model.OpnSenseDocument) {
	b.WriteVLANTable(md.H3("VLAN Configuration"), data.VLANs.VLAN)
}

// buildVLANSection builds the VLAN configuration section wrapper.
func (b *MarkdownBuilder) buildVLANSection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeVLANSection(md, data)
	return md.String()
}

// writeStaticRoutesSection writes the static routes section to the markdown instance.
func (b *MarkdownBuilder) writeStaticRoutesSection(md *markdown.Markdown, data *model.OpnSenseDocument) {
	b.WriteStaticRoutesTable(md.H3("Static Routes"), data.StaticRoutes.Route)
}

// buildStaticRoutesSection builds the static routes section wrapper.
func (b *MarkdownBuilder) buildStaticRoutesSection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeStaticRoutesSection(md, data)
	return md.String()
}

// writeHASection writes the High Availability and CARP configuration section to the markdown instance.
func (b *MarkdownBuilder) writeHASection(md *markdown.Markdown, data *model.OpnSenseDocument) {
	md.H3("High Availability & CARP")

	// Virtual IP Addresses
	if data.VirtualIP.Vip == "" {
		md.H4("Virtual IP Addresses (CARP)").
			PlainText(markdown.Italic("No virtual IPs configured"))
	} else {
		md.H4("Virtual IP Addresses (CARP)").
			Table(markdown.TableSet{
				Header: []string{"VIP Address", "Type"},
				Rows: [][]string{
					{formatters.EscapeTableContent(data.VirtualIP.Vip), "CARP"},
				},
			})
	}

	// HA Synchronization Settings
	hasync := data.HighAvailabilitySync

	if hasync.Pfsyncinterface == "" && hasync.Synchronizetoip == "" {
		md.H4("HA Synchronization Settings").
			PlainText(markdown.Italic("No HA synchronization configured"))
	} else {
		md.H4("HA Synchronization Settings").
			Table(markdown.TableSet{
				Header: []string{"Setting", "Value"},
				Rows: [][]string{
					{"**pfSync Interface**", formatters.EscapeTableContent(hasync.Pfsyncinterface)},
					{"**pfSync Peer IP**", formatters.EscapeTableContent(hasync.Pfsyncpeerip)},
					{"**Configuration Sync IP**", formatters.EscapeTableContent(hasync.Synchronizetoip)},
					{"**Sync Username**", formatters.EscapeTableContent(hasync.Username)},
					{"**Disable Preempt**", formatters.FormatBoolean(hasync.Disablepreempt)},
					{"**pfSync Version**", hasync.Pfsyncversion},
				},
			})
	}
}

// BuildHASection builds the High Availability and CARP configuration section.
func (b *MarkdownBuilder) BuildHASection(data *model.OpnSenseDocument) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeHASection(md, data)
	return md.String()
}
