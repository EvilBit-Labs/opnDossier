// Package builder provides programmatic report building functionality for device configurations.
package builder

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/nao1215/markdown"
)

const destinationAny = "any"

// ReportBuilder interface defines the contract for programmatic report generation.
// This provides type-safe, compile-time guaranteed markdown generation.
type ReportBuilder interface {
	// BuildSystemSection builds the system configuration section.
	BuildSystemSection(data *common.CommonDevice) string
	// BuildNetworkSection builds the network configuration section.
	BuildNetworkSection(data *common.CommonDevice) string
	// BuildSecuritySection builds the security configuration section.
	BuildSecuritySection(data *common.CommonDevice) string
	// BuildServicesSection builds the services configuration section.
	BuildServicesSection(data *common.CommonDevice) string

	// WriteFirewallRulesTable writes a firewall rules table and returns md for chaining.
	WriteFirewallRulesTable(md *markdown.Markdown, rules []common.FirewallRule) *markdown.Markdown
	// WriteInterfaceTable writes an interfaces table and returns md for chaining.
	WriteInterfaceTable(md *markdown.Markdown, interfaces []common.Interface) *markdown.Markdown
	// WriteUserTable writes a users table and returns md for chaining.
	WriteUserTable(md *markdown.Markdown, users []common.User) *markdown.Markdown
	// WriteGroupTable writes a groups table and returns md for chaining.
	WriteGroupTable(md *markdown.Markdown, groups []common.Group) *markdown.Markdown
	// WriteSysctlTable writes a sysctl tunables table and returns md for chaining.
	WriteSysctlTable(md *markdown.Markdown, sysctl []common.SysctlItem) *markdown.Markdown
	// WriteOutboundNATTable writes an outbound NAT rules table and returns md for chaining.
	WriteOutboundNATTable(md *markdown.Markdown, rules []common.NATRule) *markdown.Markdown
	// WriteInboundNATTable writes an inbound NAT/port forward rules table and returns md for chaining.
	WriteInboundNATTable(md *markdown.Markdown, rules []common.InboundNATRule) *markdown.Markdown
	// WriteVLANTable writes a VLAN configurations table and returns md for chaining.
	WriteVLANTable(md *markdown.Markdown, vlans []common.VLAN) *markdown.Markdown
	// WriteStaticRoutesTable writes a static routes table and returns md for chaining.
	WriteStaticRoutesTable(md *markdown.Markdown, routes []common.StaticRoute) *markdown.Markdown
	// WriteDHCPSummaryTable writes a DHCP summary table and returns md for chaining.
	WriteDHCPSummaryTable(md *markdown.Markdown, scopes []common.DHCPScope) *markdown.Markdown
	// WriteDHCPStaticLeasesTable writes a static leases table and returns md for chaining.
	WriteDHCPStaticLeasesTable(md *markdown.Markdown, leases []common.DHCPStaticLease) *markdown.Markdown

	// BuildIPsecSection builds the IPsec VPN configuration section.
	BuildIPsecSection(data *common.CommonDevice) string
	// BuildOpenVPNSection builds the OpenVPN configuration section.
	BuildOpenVPNSection(data *common.CommonDevice) string
	// BuildHASection builds the High Availability and CARP configuration section.
	BuildHASection(data *common.CommonDevice) string
	// BuildIDSSection builds the IDS/Suricata configuration section.
	BuildIDSSection(data *common.CommonDevice) string

	// BuildStandardReport generates a standard configuration report.
	BuildStandardReport(data *common.CommonDevice) (string, error)
	// BuildComprehensiveReport generates a comprehensive configuration report.
	BuildComprehensiveReport(data *common.CommonDevice) (string, error)
}

// MarkdownBuilder implements the ReportBuilder interface with comprehensive
// programmatic markdown generation capabilities.
type MarkdownBuilder struct {
	config      *common.CommonDevice
	logger      *logging.Logger
	generated   time.Time
	toolVersion string
}

// NewMarkdownBuilder creates a new MarkdownBuilder instance.
func NewMarkdownBuilder() *MarkdownBuilder {
	logger, err := logging.New(logging.Config{Level: "info"})
	if err != nil {
		logger = &logging.Logger{}
	}
	return &MarkdownBuilder{
		generated:   time.Now(),
		toolVersion: constants.Version,
		logger:      logger,
	}
}

// NewMarkdownBuilderWithConfig creates a new MarkdownBuilder instance with configuration.
func NewMarkdownBuilderWithConfig(config *common.CommonDevice, logger *logging.Logger) *MarkdownBuilder {
	if logger == nil {
		var err error
		logger, err = logging.New(logging.Config{Level: "info"})
		if err != nil {
			logger = &logging.Logger{}
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
func (b *MarkdownBuilder) writeSystemSection(md *markdown.Markdown, data *common.CommonDevice) {
	sys := data.System

	md.H2("System Configuration").
		H3("Basic Information").
		PlainTextf("%s: %s", markdown.Bold("Hostname"), sys.Hostname).LF().
		PlainTextf("%s: %s", markdown.Bold("Domain"), sys.Domain).LF()

	if sys.Optimization != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Optimization"), sys.Optimization)
	}

	if sys.Timezone != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Timezone"), sys.Timezone)
	}

	if sys.Language != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Language"), sys.Language)
	}

	if sys.WebGUI.Protocol != "" {
		md.H3("Web GUI Configuration")
		md.PlainTextf("%s: %s", markdown.Bold("Protocol"), sys.WebGUI.Protocol)
	}

	md.H3("System Settings").
		PlainTextf(
			"%s: %s",
			markdown.Bold("DNS Allow Override"),
			formatters.FormatBool(sys.DNSAllowOverride),
		).LF().
		PlainTextf("%s: %d", markdown.Bold("Next UID"), sys.NextUID).LF().
		PlainTextf("%s: %d", markdown.Bold("Next GID"), sys.NextGID).LF()

	if len(sys.TimeServers) > 0 {
		md.PlainTextf("%s: %s", markdown.Bold("Time Servers"), strings.Join(sys.TimeServers, ", "))
	}

	if len(sys.DNSServers) > 0 {
		md.PlainTextf("%s: %s", markdown.Bold("DNS Server"), strings.Join(sys.DNSServers, ", "))
	}

	md.H3("Hardware Offloading").
		PlainTextf(
			"%s: %s",
			markdown.Bold("Disable NAT Reflection"),
			formatters.FormatBool(sys.DisableNATReflection),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Use Virtual Terminal"),
			formatters.FormatBool(sys.UseVirtualTerminal),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Disable Console Menu"),
			formatters.FormatBool(sys.DisableConsoleMenu),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Disable VLAN HW Filter"),
			formatters.FormatBool(sys.DisableVLANHWFilter),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Disable Checksum Offloading"),
			formatters.FormatBool(sys.DisableChecksumOffloading),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Disable Segmentation Offloading"),
			formatters.FormatBool(sys.DisableSegmentationOffloading),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Disable Large Receive Offloading"),
			formatters.FormatBool(sys.DisableLargeReceiveOffloading),
		).LF().
		PlainTextf("%s: %s", markdown.Bold("IPv6 Allow"), formatters.FormatBool(sys.IPv6Allow)).LF()

	md.H3("Power Management").
		PlainTextf(
			"%s: %s",
			markdown.Bold("Powerd AC Mode"),
			formatters.GetPowerModeDescriptionCompact(sys.PowerdACMode),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Powerd Battery Mode"),
			formatters.GetPowerModeDescriptionCompact(sys.PowerdBatteryMode),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Powerd Normal Mode"),
			formatters.GetPowerModeDescriptionCompact(sys.PowerdNormalMode),
		).LF()

	md.H3("System Features").
		PlainTextf(
			"%s: %s",
			markdown.Bold("PF Share Forward"),
			formatters.FormatBool(sys.PfShareForward),
		).LF().
		PlainTextf("%s: %s", markdown.Bold("LB Use Sticky"), formatters.FormatBool(sys.LbUseSticky)).
		LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("RRD Backup"),
			formatters.FormatBool(sys.RrdBackup),
		).LF().
		PlainTextf(
			"%s: %s",
			markdown.Bold("Netflow Backup"),
			formatters.FormatBool(sys.NetflowBackup),
		)

	if sys.Bogons.Interval != "" {
		md.H3("Bogons Configuration").
			PlainTextf("%s: %s", markdown.Bold("Interval"), sys.Bogons.Interval)
	}

	if sys.SSH.Group != "" {
		md.H3("SSH Configuration").
			PlainTextf("%s: %s", markdown.Bold("Group"), sys.SSH.Group)
	}

	if sys.Firmware.Version != "" {
		md.H3("Firmware Information").
			PlainTextf("%s: %s", markdown.Bold("Version"), sys.Firmware.Version)
	}

	if len(data.Users) > 0 {
		b.WriteUserTable(md.H3("System Users"), data.Users)
	}

	if len(data.Groups) > 0 {
		b.WriteGroupTable(md.H3("System Groups"), data.Groups)
	}
}

// BuildSystemSection builds the system configuration section.
func (b *MarkdownBuilder) BuildSystemSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeSystemSection(md, data)
	return md.String()
}

// writeNetworkSection writes the network configuration section to the markdown instance.
func (b *MarkdownBuilder) writeNetworkSection(md *markdown.Markdown, data *common.CommonDevice) {
	b.WriteInterfaceTable(
		md.H2("Network Configuration").H3("Interfaces"),
		data.Interfaces,
	)

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

// BuildNetworkSection builds the network configuration section.
func (b *MarkdownBuilder) BuildNetworkSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeNetworkSection(md, data)
	return md.String()
}

// writeSecuritySection writes the security configuration section to the markdown instance.
func (b *MarkdownBuilder) writeSecuritySection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H2("Security Configuration").
		H3("NAT Configuration")

	natSummary := data.NATSummary()
	if natSummary.Mode != "" || data.NAT.OutboundMode != "" {
		md.H4("NAT Summary")
		mode := natSummary.Mode
		if mode == "" {
			mode = data.NAT.OutboundMode
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

	if len(data.FirewallRules) > 0 {
		b.WriteFirewallRulesTable(md.H3("Firewall Rules"), data.FirewallRules)
	}

	// IDS/Suricata Configuration
	b.writeIDSSection(md, data)
}

// BuildSecuritySection builds the security configuration section.
func (b *MarkdownBuilder) BuildSecuritySection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeSecuritySection(md, data)
	return md.String()
}

// writeIDSSection writes the IDS/Suricata configuration section to the markdown instance.
func (b *MarkdownBuilder) writeIDSSection(md *markdown.Markdown, data *common.CommonDevice) {
	ids := data.IDS
	if ids == nil || !ids.Enabled {
		return
	}

	md.H3("Intrusion Detection System (IDS/Suricata)")

	// Detection mode
	detectionMode := "IDS"
	if ids.IPSMode {
		detectionMode = "IPS"
	}

	// Configuration summary table
	configRows := [][]string{
		{"**Status**", "Enabled"},
		{"**Mode**", detectionMode},
	}

	if ids.Detect.Profile != "" {
		configRows = append(configRows, []string{"**Detection Profile**", ids.Detect.Profile})
	}

	if ids.MPMAlgo != "" {
		configRows = append(configRows, []string{"**Pattern Matching Algorithm**", ids.MPMAlgo})
	}

	configRows = append(
		configRows,
		[]string{"**Promiscuous Mode**", formatters.FormatBoolStatus(ids.Promiscuous)},
	)

	if ids.DefaultPacketSize != "" {
		configRows = append(configRows, []string{"**Default Packet Size**", ids.DefaultPacketSize})
	}

	md.H4("Configuration Summary").
		Table(markdown.TableSet{
			Header: []string{"Setting", "Value"},
			Rows:   configRows,
		})

	// Monitored interfaces
	if len(ids.Interfaces) > 0 {
		md.H4("Monitored Interfaces")
		interfaceItems := make([]string, 0, len(ids.Interfaces))
		for _, iface := range ids.Interfaces {
			interfaceItems = append(interfaceItems, fmt.Sprintf("`%s`", iface))
		}
		md.BulletList(interfaceItems...)
	}

	// Home networks
	if len(ids.HomeNetworks) > 0 {
		md.H4("Home Networks")
		netItems := make([]string, 0, len(ids.HomeNetworks))
		for _, net := range ids.HomeNetworks {
			netItems = append(netItems, fmt.Sprintf("`%s`", net))
		}
		md.BulletList(netItems...)
	}

	// Logging configuration
	logRows := [][]string{
		{"**Syslog**", formatters.FormatBoolStatus(ids.SyslogEnabled)},
		{"**EVE Syslog**", formatters.FormatBoolStatus(ids.SyslogEveEnabled)},
	}

	if ids.LogPayload != "" {
		logRows = append(logRows, []string{"**Payload Logging**", ids.LogPayload})
	}

	if ids.Verbosity != "" {
		logRows = append(logRows, []string{"**Verbosity**", ids.Verbosity})
	}

	if ids.AlertLogrotate != "" {
		logRows = append(logRows, []string{"**Log Rotation**", ids.AlertLogrotate})
	}

	if ids.AlertSaveLogs != "" {
		logRows = append(logRows, []string{"**Log Retention**", ids.AlertSaveLogs})
	}

	md.H4("Logging Configuration").
		Table(markdown.TableSet{
			Header: []string{"Setting", "Value"},
			Rows:   logRows,
		})

	// Security notes
	if !ids.IPSMode {
		md.Tip(
			"Consider enabling IPS mode for active threat prevention. IDS mode only detects threats without blocking them.",
		)
	} else {
		md.Note(
			"IPS mode is active. Suricata will actively block detected threats based on configured rules.",
		)
	}

	if ids.SyslogEveEnabled {
		md.Note(
			"EVE JSON logging is enabled via syslog, which supports SIEM integration for centralized threat monitoring.",
		)
	}
}

// BuildIDSSection builds the IDS/Suricata configuration section.
func (b *MarkdownBuilder) BuildIDSSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeIDSSection(md, data)
	return md.String()
}

// writeServicesSection writes the service configuration section to the markdown instance.
func (b *MarkdownBuilder) writeServicesSection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H2("Service Configuration").
		H3("DHCP Server")

	// DHCP Summary Table
	b.WriteDHCPSummaryTable(md, data.DHCP)

	// Per-scope detailed sections (only for scopes with additional config)
	for _, dhcp := range data.DHCP {
		hasStaticLeases := len(dhcp.StaticLeases) > 0
		hasNumberOptions := len(dhcp.NumberOptions) > 0
		hasAdvanced := HasAdvancedDHCPConfig(dhcp)
		hasIPv6 := HasDHCPv6Config(dhcp)

		if !hasStaticLeases && !hasNumberOptions && !hasAdvanced && !hasIPv6 {
			continue
		}

		// Capitalize interface name for header (defensive check for empty string)
		headerName := dhcp.Interface
		if dhcp.Interface != "" {
			headerName = strings.ToUpper(dhcp.Interface[:1]) + strings.ToLower(dhcp.Interface[1:])
		}
		md.H4(headerName + " DHCP Details")

		// Static leases table
		if hasStaticLeases {
			md.PlainTextf("%s:", markdown.Bold("Static Leases")).LF()
			b.WriteDHCPStaticLeasesTable(md, dhcp.StaticLeases)
		}

		// Number options table
		if hasNumberOptions {
			md.PlainTextf("%s:", markdown.Bold("DHCP Number Options")).LF()
			numOptRows := make([][]string, 0, len(dhcp.NumberOptions))
			for _, opt := range dhcp.NumberOptions {
				numOptRows = append(numOptRows, []string{
					formatters.EscapeTableContent(opt.Number),
					formatters.EscapeTableContent(opt.Type),
					formatters.EscapeTableContent(opt.Value),
				})
			}
			md.Table(markdown.TableSet{
				Header: []string{"Option Number", "Type", "Value"},
				Rows:   numOptRows,
			})
		}

		// Advanced options section
		if hasAdvanced {
			md.PlainTextf("%s:", markdown.Bold("Advanced DHCP Options")).LF()
			advItems := buildAdvancedDHCPItems(dhcp)
			md.BulletList(advItems...)
		}

		// DHCPv6 options section
		if hasIPv6 {
			md.PlainTextf("%s:", markdown.Bold("DHCPv6 Options")).LF()
			v6Items := buildDHCPv6Items(dhcp)
			md.BulletList(v6Items...)
		}
	}

	md.H3("DNS Resolver (Unbound)")
	if data.DNS.Unbound.Enabled {
		md.PlainTextf("%s: %s", markdown.Bold("Enabled"), formatters.FormatBool(data.DNS.Unbound.Enabled)).LF()
	}

	md.H3("SNMP")
	if data.SNMP.SysLocation != "" {
		md.PlainTextf("%s: %s", markdown.Bold("System Location"), data.SNMP.SysLocation).LF()
	}
	if data.SNMP.SysContact != "" {
		md.PlainTextf("%s: %s", markdown.Bold("System Contact"), data.SNMP.SysContact).LF()
	}
	if data.SNMP.ROCommunity != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Read-Only Community"), data.SNMP.ROCommunity).LF()
	}

	md.H3("NTP")
	if data.NTP.PreferredServer != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Preferred Server"), data.NTP.PreferredServer).LF()
	}

	if len(data.LoadBalancer.MonitorTypes) > 0 {
		rows := make([][]string, 0, len(data.LoadBalancer.MonitorTypes))
		for _, monitor := range data.LoadBalancer.MonitorTypes {
			rows = append(rows, []string{monitor.Name, monitor.Type, monitor.Description})
		}
		md.H3("Load Balancer Monitors").
			Table(markdown.TableSet{
				Header: []string{"Name", "Type", "Description"},
				Rows:   rows,
			})
	}
}

// BuildServicesSection builds the service configuration section.
func (b *MarkdownBuilder) BuildServicesSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeServicesSection(md, data)
	return md.String()
}

// WriteFirewallRulesTable writes a firewall rules table and returns md for chaining.
func (b *MarkdownBuilder) WriteFirewallRulesTable(
	md *markdown.Markdown,
	rules []common.FirewallRule,
) *markdown.Markdown {
	return md.Table(*BuildFirewallRulesTableSet(rules))
}

// BuildFirewallRulesTableSet builds the table data for firewall rules.
func BuildFirewallRulesTableSet(rules []common.FirewallRule) *markdown.TableSet {
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
		"Dest Port",
		"Enabled",
		"Description",
	}

	rows := make([][]string, 0, len(rules))
	for i, rule := range rules {
		source := rule.Source.Address
		if source == "" {
			source = destinationAny
		}

		dest := rule.Destination.Address
		if dest == "" {
			dest = destinationAny
		}

		interfaceLinks := formatters.FormatInterfacesAsLinks(rule.Interfaces)

		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			interfaceLinks,
			rule.Type,
			rule.IPProtocol,
			rule.Protocol,
			source,
			dest,
			rule.Target,
			formatters.EscapeTableContent(rule.Source.Port),
			formatters.EscapeTableContent(rule.Destination.Port),
			formatters.FormatBoolInverted(rule.Disabled),
			formatters.EscapeTableContent(rule.Description),
		})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// WriteOutboundNATTable writes an outbound NAT rules table and returns md for chaining.
func (b *MarkdownBuilder) WriteOutboundNATTable(md *markdown.Markdown, rules []common.NATRule) *markdown.Markdown {
	return md.Table(*BuildOutboundNATTableSet(rules))
}

// BuildOutboundNATTableSet builds the table data for outbound NAT rules.
func BuildOutboundNATTableSet(rules []common.NATRule) *markdown.TableSet {
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
			source := rule.Source.Address
			if source == "" {
				source = destinationAny
			}

			dest := rule.Destination.Address
			if dest == "" {
				dest = destinationAny
			}

			protocol := rule.Protocol
			if protocol == "" {
				protocol = destinationAny
			}

			target := rule.Target
			if target != "" {
				target = fmt.Sprintf("`%s`", target)
			}

			status := "**Active**"
			if rule.Disabled {
				status = "**Disabled**"
			}

			interfaceLinks := formatters.FormatInterfacesAsLinks(rule.Interfaces)

			rows = append(rows, []string{
				strconv.Itoa(i + 1),
				"⬆️ Outbound",
				interfaceLinks,
				source,
				dest,
				target,
				protocol,
				formatters.EscapeTableContent(rule.Description),
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
func (b *MarkdownBuilder) WriteInboundNATTable(
	md *markdown.Markdown,
	rules []common.InboundNATRule,
) *markdown.Markdown {
	return md.Table(*BuildInboundNATTableSet(rules))
}

// BuildInboundNATTableSet builds the table data for inbound NAT rules.
func BuildInboundNATTableSet(rules []common.InboundNATRule) *markdown.TableSet {
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
				protocol = destinationAny
			}

			targetIP := rule.InternalIP
			if targetIP != "" {
				targetIP = fmt.Sprintf("`%s`", targetIP)
			}

			status := "**Active**"
			if rule.Disabled {
				status = "**Disabled**"
			}

			interfaceLinks := formatters.FormatInterfacesAsLinks(rule.Interfaces)

			rows = append(rows, []string{
				strconv.Itoa(i + 1),
				"⬇️ Inbound",
				interfaceLinks,
				rule.ExternalPort,
				targetIP,
				rule.InternalPort,
				protocol,
				formatters.EscapeTableContent(rule.Description),
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
func (b *MarkdownBuilder) WriteInterfaceTable(md *markdown.Markdown, interfaces []common.Interface) *markdown.Markdown {
	return md.Table(*BuildInterfaceTableSet(interfaces))
}

// BuildInterfaceTableSet builds the table data for network interfaces.
func BuildInterfaceTableSet(interfaces []common.Interface) *markdown.TableSet {
	headers := []string{"Name", "Description", "IP Address", "CIDR", "Enabled"}

	rows := make([][]string, 0, len(interfaces))
	for _, iface := range interfaces {
		description := iface.Description
		if description == "" {
			description = iface.PhysicalIf
		}

		cidr := ""
		if iface.Subnet != "" {
			cidr = "/" + iface.Subnet
		}

		rows = append(rows, []string{
			fmt.Sprintf("`%s`", iface.Name),
			fmt.Sprintf("`%s`", formatters.EscapeTableContent(description)),
			fmt.Sprintf("`%s`", iface.IPAddress),
			cidr,
			formatters.FormatBool(iface.Enabled),
		})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// WriteUserTable writes a users table and returns md for chaining.
func (b *MarkdownBuilder) WriteUserTable(md *markdown.Markdown, users []common.User) *markdown.Markdown {
	return md.Table(*BuildUserTableSet(users))
}

// BuildUserTableSet builds the table data for system users.
func BuildUserTableSet(users []common.User) *markdown.TableSet {
	headers := []string{"Name", "Description", "Group", "Scope"}

	rows := make([][]string, 0, len(users))
	for _, user := range users {
		rows = append(rows, []string{
			formatters.EscapeTableContent(user.Name),
			formatters.EscapeTableContent(user.Description),
			formatters.EscapeTableContent(user.GroupName),
			formatters.EscapeTableContent(user.Scope),
		})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// WriteGroupTable writes a groups table and returns md for chaining.
func (b *MarkdownBuilder) WriteGroupTable(md *markdown.Markdown, groups []common.Group) *markdown.Markdown {
	return md.Table(*BuildGroupTableSet(groups))
}

// BuildGroupTableSet builds the table data for system groups.
func BuildGroupTableSet(groups []common.Group) *markdown.TableSet {
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
func (b *MarkdownBuilder) WriteSysctlTable(md *markdown.Markdown, sysctl []common.SysctlItem) *markdown.Markdown {
	return md.Table(*BuildSysctlTableSet(sysctl))
}

// BuildSysctlTableSet builds the table data for system tunables.
func BuildSysctlTableSet(sysctl []common.SysctlItem) *markdown.TableSet {
	headers := []string{"Tunable", "Value", "Description"}

	rows := make([][]string, 0, len(sysctl))
	for _, item := range sysctl {
		rows = append(rows, []string{
			formatters.EscapeTableContent(item.Tunable),
			formatters.EscapeTableContent(item.Value),
			formatters.EscapeTableContent(item.Description),
		})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// BuildStandardReport builds a standard markdown report.
func (b *MarkdownBuilder) BuildStandardReport(data *common.CommonDevice) (string, error) {
	if data == nil {
		return "", ErrNilDevice
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

	if len(data.Sysctl) > 0 {
		b.WriteSysctlTable(md.H2("System Tunables"), data.Sysctl)
	}

	return md.String(), nil
}

// BuildComprehensiveReport builds a comprehensive markdown report.
func (b *MarkdownBuilder) BuildComprehensiveReport(data *common.CommonDevice) (string, error) {
	if data == nil {
		return "", ErrNilDevice
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
			markdown.Link("Intrusion Detection System", "#intrusion-detection-system-idssuricata"),
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

	if len(data.Sysctl) > 0 {
		b.WriteSysctlTable(md.H2("System Tunables"), data.Sysctl)
	}

	return md.String(), nil
}

func buildInterfaceDetails(md *markdown.Markdown, iface common.Interface) {
	// Build a list of interface properties that are set
	if iface.PhysicalIf != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Physical Interface"), iface.PhysicalIf).LF()
	}
	md.PlainTextf("%s: %s", markdown.Bold("Enabled"), formatters.FormatBool(iface.Enabled)).LF()
	if iface.IPAddress != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv4 Address"), iface.IPAddress).LF()
	}
	if iface.Subnet != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv4 Subnet"), iface.Subnet).LF()
	}
	if iface.IPv6Address != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv6 Address"), iface.IPv6Address).LF()
	}
	if iface.SubnetV6 != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv6 Subnet"), iface.SubnetV6).LF()
	}
	if iface.Gateway != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Gateway"), iface.Gateway).LF()
	}
	if iface.MTU != "" {
		md.PlainTextf("%s: %s", markdown.Bold("MTU"), iface.MTU).LF()
	}
	md.PlainTextf("%s: %s", markdown.Bold("Block Private Networks"), formatters.FormatBool(iface.BlockPrivate)).LF()
	md.PlainTextf("%s: %s", markdown.Bold("Block Bogon Networks"), formatters.FormatBool(iface.BlockBogons))
}

// WriteVLANTable writes a VLAN configurations table and returns md for chaining.
func (b *MarkdownBuilder) WriteVLANTable(md *markdown.Markdown, vlans []common.VLAN) *markdown.Markdown {
	return md.Table(*BuildVLANTableSet(vlans))
}

// BuildVLANTableSet builds the table data for VLAN configurations.
func BuildVLANTableSet(vlans []common.VLAN) *markdown.TableSet {
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
				formatters.EscapeTableContent(vlan.VLANIf),
				formatters.EscapeTableContent(vlan.PhysicalIf),
				vlan.Tag,
				formatters.EscapeTableContent(vlan.Description),
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
func (b *MarkdownBuilder) WriteStaticRoutesTable(
	md *markdown.Markdown,
	routes []common.StaticRoute,
) *markdown.Markdown {
	return md.Table(*BuildStaticRoutesTableSet(routes))
}

// BuildStaticRoutesTableSet builds the table data for static routes.
func BuildStaticRoutesTableSet(routes []common.StaticRoute) *markdown.TableSet {
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
				formatters.EscapeTableContent(route.Description),
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
func (b *MarkdownBuilder) WriteDHCPSummaryTable(md *markdown.Markdown, scopes []common.DHCPScope) *markdown.Markdown {
	return md.Table(*BuildDHCPSummaryTableSet(scopes))
}

// BuildDHCPSummaryTableSet builds the table data for DHCP scope summary.
func BuildDHCPSummaryTableSet(scopes []common.DHCPScope) *markdown.TableSet {
	headers := []string{
		"Interface",
		"Enabled",
		"Gateway",
		"Range Start",
		"Range End",
		"DNS",
		"WINS",
		"NTP",
	}

	rows := make([][]string, 0, len(scopes))

	if len(scopes) == 0 {
		rows = append(rows, []string{
			"-", "-", "-", "-", "-", "-", "-",
			"No DHCP scopes configured",
		})
	} else {
		for _, scope := range scopes {
			rows = append(rows, []string{
				formatters.EscapeTableContent(scope.Interface),
				formatters.FormatBool(scope.Enabled),
				formatters.EscapeTableContent(scope.Gateway),
				formatters.EscapeTableContent(scope.Range.From),
				formatters.EscapeTableContent(scope.Range.To),
				formatters.EscapeTableContent(scope.DNSServer),
				formatters.EscapeTableContent(scope.WINSServer),
				formatters.EscapeTableContent(scope.NTPServer),
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
	leases []common.DHCPStaticLease,
) *markdown.Markdown {
	return md.Table(*BuildDHCPStaticLeasesTableSet(leases))
}

// BuildDHCPStaticLeasesTableSet builds the table data for static DHCP leases.
func BuildDHCPStaticLeasesTableSet(leases []common.DHCPStaticLease) *markdown.TableSet {
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
				formatters.EscapeTableContent(lease.MAC),
				formatters.EscapeTableContent(lease.IPAddress),
				formatters.EscapeTableContent(lease.CID),
				formatters.EscapeTableContent(lease.Filename),
				formatters.EscapeTableContent(lease.Rootpath),
				FormatLeaseTime(lease.DefaultLeaseTime),
				FormatLeaseTime(lease.MaxLeaseTime),
				formatters.EscapeTableContent(lease.Description),
			})
		}
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// writeIPsecSection writes the IPsec VPN configuration section to the markdown instance.
func (b *MarkdownBuilder) writeIPsecSection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H3("IPsec VPN Configuration")

	ipsec := data.VPN.IPsec
	if !ipsec.Enabled {
		md.PlainText(markdown.Italic("No IPsec configuration present"))
		return
	}

	md.H4("General Configuration").
		Table(markdown.TableSet{
			Header: []string{"Setting", "Value"},
			Rows: [][]string{
				{"**Enabled**", formatters.FormatBool(ipsec.Enabled)},
			},
		})

	md.Note("Phase 1/Phase 2 tunnel configurations require additional parser implementation")
}

// BuildIPsecSection builds the IPsec VPN configuration section.
func (b *MarkdownBuilder) BuildIPsecSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeIPsecSection(md, data)
	return md.String()
}

// writeOpenVPNSection writes the OpenVPN configuration section to the markdown instance.
func (b *MarkdownBuilder) writeOpenVPNSection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H3("OpenVPN Configuration")

	openvpn := data.VPN.OpenVPN

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
				server.LocalPort,
				formatters.EscapeTableContent(server.TunnelNetwork),
				formatters.EscapeTableContent(server.RemoteNetwork),
				formatters.EscapeTableContent(server.CertRef),
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
				formatters.EscapeTableContent(client.ServerAddr),
				client.ServerPort,
				client.Mode,
				client.Protocol,
				formatters.EscapeTableContent(client.CertRef),
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
}

// BuildOpenVPNSection builds the OpenVPN configuration section with servers, clients, and CSC.
func (b *MarkdownBuilder) BuildOpenVPNSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeOpenVPNSection(md, data)
	return md.String()
}

// writeVLANSection writes the VLAN configuration section to the markdown instance.
func (b *MarkdownBuilder) writeVLANSection(md *markdown.Markdown, data *common.CommonDevice) {
	b.WriteVLANTable(md.H3("VLAN Configuration"), data.VLANs)
}

// buildVLANSection builds the VLAN configuration section wrapper.
func (b *MarkdownBuilder) buildVLANSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeVLANSection(md, data)
	return md.String()
}

// writeStaticRoutesSection writes the static routes section to the markdown instance.
func (b *MarkdownBuilder) writeStaticRoutesSection(md *markdown.Markdown, data *common.CommonDevice) {
	b.WriteStaticRoutesTable(md.H3("Static Routes"), data.Routing.StaticRoutes)
}

// buildStaticRoutesSection builds the static routes section wrapper.
func (b *MarkdownBuilder) buildStaticRoutesSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeStaticRoutesSection(md, data)
	return md.String()
}

// writeHASection writes the High Availability and CARP configuration section to the markdown instance.
func (b *MarkdownBuilder) writeHASection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H3("High Availability & CARP")

	// Virtual IP Addresses
	if len(data.VirtualIPs) == 0 {
		md.H4("Virtual IP Addresses (CARP)").
			PlainText(markdown.Italic("No virtual IPs configured"))
	} else {
		vipRows := make([][]string, 0, len(data.VirtualIPs))
		for _, vip := range data.VirtualIPs {
			vipRows = append(vipRows, []string{
				formatters.EscapeTableContent(vip.Subnet),
				vip.Mode,
			})
		}
		md.H4("Virtual IP Addresses (CARP)").
			Table(markdown.TableSet{
				Header: []string{"VIP Address", "Type"},
				Rows:   vipRows,
			})
	}

	// HA Synchronization Settings
	hasync := data.HighAvailability

	if hasync.PfsyncInterface == "" && hasync.SynchronizeToIP == "" {
		md.H4("HA Synchronization Settings").
			PlainText(markdown.Italic("No HA synchronization configured"))
	} else {
		md.H4("HA Synchronization Settings").
			Table(markdown.TableSet{
				Header: []string{"Setting", "Value"},
				Rows: [][]string{
					{"**pfSync Interface**", formatters.EscapeTableContent(hasync.PfsyncInterface)},
					{"**pfSync Peer IP**", formatters.EscapeTableContent(hasync.PfsyncPeerIP)},
					{"**Configuration Sync IP**", formatters.EscapeTableContent(hasync.SynchronizeToIP)},
					{"**Sync Username**", formatters.EscapeTableContent(hasync.Username)},
					{"**Disable Preempt**", formatters.FormatBool(hasync.DisablePreempt)},
					{"**pfSync Version**", hasync.PfsyncVersion},
				},
			})
	}
}

// BuildHASection builds the High Availability and CARP configuration section.
func (b *MarkdownBuilder) BuildHASection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeHASection(md, data)
	return md.String()
}
