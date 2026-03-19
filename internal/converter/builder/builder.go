// Package builder provides programmatic report building functionality for device configurations.
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
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/nao1215/markdown"
)

// destinationAny is the canonical string used to represent an unrestricted destination in firewall rules.
const destinationAny = "any"

// SectionBuilder defines methods for building individual report sections.
// Each method renders a specific configuration domain into a markdown string.
type SectionBuilder interface {
	// BuildSystemSection builds the system configuration section.
	BuildSystemSection(data *common.CommonDevice) string
	// BuildNetworkSection builds the network configuration section.
	BuildNetworkSection(data *common.CommonDevice) string
	// BuildSecuritySection builds the security configuration section.
	BuildSecuritySection(data *common.CommonDevice) string
	// BuildServicesSection builds the services configuration section.
	BuildServicesSection(data *common.CommonDevice) string
	// BuildIPsecSection builds the IPsec VPN configuration section.
	BuildIPsecSection(data *common.CommonDevice) string
	// BuildOpenVPNSection builds the OpenVPN configuration section.
	BuildOpenVPNSection(data *common.CommonDevice) string
	// BuildHASection builds the High Availability and CARP configuration section.
	BuildHASection(data *common.CommonDevice) string
	// BuildIDSSection builds the IDS/Suricata configuration section.
	BuildIDSSection(data *common.CommonDevice) string
	// BuildAuditSection builds the compliance audit section from the device's ComplianceChecks.
	BuildAuditSection(data *common.CommonDevice) string
	// SetIncludeTunables configures whether all system tunables are included in the report.
	// When false, only tunables matching the security prefixes used by
	// formatters.FilterSystemTunables are shown.
	SetIncludeTunables(v bool)
}

// TableWriter defines methods for writing data tables into a markdown instance.
// Each method appends a formatted table and returns the markdown for chaining.
type TableWriter interface {
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
}

// ReportComposer defines methods for composing full configuration reports.
// Each method assembles multiple sections into a complete markdown document.
type ReportComposer interface {
	// BuildStandardReport generates a standard configuration report.
	BuildStandardReport(data *common.CommonDevice) (string, error)
	// BuildComprehensiveReport generates a comprehensive configuration report.
	BuildComprehensiveReport(data *common.CommonDevice) (string, error)
}

// ReportBuilder defines the contract for programmatic report generation.
// It composes SectionBuilder, TableWriter, and ReportComposer to provide
// type-safe, compile-time guaranteed markdown generation.
type ReportBuilder interface {
	SectionBuilder
	TableWriter
	ReportComposer
}

// Compile-time assertion that MarkdownBuilder satisfies ReportBuilder.
var _ ReportBuilder = (*MarkdownBuilder)(nil)

// MarkdownBuilder implements the ReportBuilder interface with comprehensive
// programmatic markdown generation capabilities.
// MarkdownBuilder is not safe for concurrent use. Create a new instance per goroutine.
type MarkdownBuilder struct {
	config          *common.CommonDevice
	logger          *logging.Logger
	generated       time.Time
	toolVersion     string
	includeTunables bool
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

// SetIncludeTunables configures whether all system tunables are included in the report.
// When false, only security-relevant tunables are shown (filtered by formatters.FilterSystemTunables).
// Not safe for concurrent use — call in the same goroutine as Build/Write methods.
func (b *MarkdownBuilder) SetIncludeTunables(v bool) {
	b.includeTunables = v
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

// BuildAuditSection builds the compliance audit section from the device's ComplianceChecks.
// If ComplianceChecks is nil, it returns an empty string.
func (b *MarkdownBuilder) BuildAuditSection(data *common.CommonDevice) string {
	if data == nil || data.ComplianceChecks == nil {
		return ""
	}

	cc := data.ComplianceChecks

	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	// Summary table
	var totalFindings int
	if cc.Summary != nil {
		totalFindings = cc.Summary.TotalFindings
	} else {
		// Compute from direct findings plus plugin results if summary is nil
		totalFindings = len(cc.Findings)
		for _, pluginName := range slices.Sorted(maps.Keys(cc.PluginResults)) {
			pr := cc.PluginResults[pluginName]
			if pr.Summary != nil {
				totalFindings += pr.Summary.TotalFindings
			} else {
				totalFindings += len(pr.Findings)
			}
		}
	}

	md.H2("Compliance Audit Summary")
	md.Table(markdown.TableSet{
		Header: []string{"Metric", "Value"},
		Rows: [][]string{
			{"Mode", cc.Mode},
			{"Total Findings", strconv.Itoa(totalFindings)},
		},
	})

	// Plugin compliance results
	if len(cc.PluginResults) > 0 {
		md.H3("Plugin Compliance Results")
		for _, pluginName := range slices.Sorted(maps.Keys(cc.PluginResults)) {
			result := cc.PluginResults[pluginName]
			md.H4(pluginName)

			if result.Summary == nil {
				md.BulletList("Summary: no data available")
				continue
			}

			items := []string{fmt.Sprintf("Summary: %d findings", result.Summary.TotalFindings)}
			if result.Summary.CriticalFindings > 0 {
				items = append(items, fmt.Sprintf("Critical: %d", result.Summary.CriticalFindings))
			}
			if result.Summary.HighFindings > 0 {
				items = append(items, fmt.Sprintf("High: %d", result.Summary.HighFindings))
			}
			if result.Summary.MediumFindings > 0 {
				items = append(items, fmt.Sprintf("Medium: %d", result.Summary.MediumFindings))
			}
			if result.Summary.LowFindings > 0 {
				items = append(items, fmt.Sprintf("Low: %d", result.Summary.LowFindings))
			}
			md.BulletList(items...)
		}
	}

	// Security findings table
	if len(cc.Findings) > 0 {
		md.H3("Security Findings")
		findingsTable := markdown.TableSet{
			Header: []string{"Severity", "Component", "Title", "Recommendation"},
			Rows:   make([][]string, 0, len(cc.Findings)),
		}
		for _, f := range cc.Findings {
			findingsTable.Rows = append(findingsTable.Rows, []string{
				EscapePipeForMarkdown(f.Severity),
				EscapePipeForMarkdown(f.Component),
				EscapePipeForMarkdown(f.Title),
				EscapePipeForMarkdown(f.Recommendation),
			})
		}
		md.Table(findingsTable)
	}

	// Per-plugin findings tables
	for _, pluginName := range slices.Sorted(maps.Keys(cc.PluginResults)) {
		result := cc.PluginResults[pluginName]
		if len(result.Findings) > 0 {
			md.H3(pluginName + " Plugin Findings")
			pluginTable := markdown.TableSet{
				Header: []string{"Severity", "Title", "Description"},
				Rows:   make([][]string, 0, len(result.Findings)),
			}
			for _, f := range result.Findings {
				pluginTable.Rows = append(pluginTable.Rows, []string{
					EscapePipeForMarkdown(f.Severity),
					EscapePipeForMarkdown(f.Title),
					EscapePipeForMarkdown(TruncateString(f.Description, MaxDescriptionLength)),
				})
			}
			md.Table(pluginTable)
		}
	}

	// Audit metadata table
	if len(cc.Metadata) > 0 {
		md.H3("Audit Metadata")
		metadataTable := markdown.TableSet{
			Header: []string{"Key", "Value"},
			Rows:   make([][]string, 0, len(cc.Metadata)),
		}
		for _, key := range slices.Sorted(maps.Keys(cc.Metadata)) {
			metadataTable.Rows = append(metadataTable.Rows, []string{
				EscapePipeForMarkdown(key),
				EscapePipeForMarkdown(fmt.Sprintf("%v", cc.Metadata[key])),
			})
		}
		md.Table(metadataTable)
	}

	//nolint:errcheck,gosec // Build writes to bytes.Buffer which cannot fail
	md.Build()

	return buf.String()
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

// standardToCItems returns the table of contents items for a standard report.
// The hasTunables parameter controls whether the "System Tunables" link is included.
func (b *MarkdownBuilder) standardToCItems(hasTunables bool) []string {
	items := []string{
		markdown.Link("System Configuration", "#system-configuration"),
		markdown.Link("Interfaces", "#interfaces"),
		markdown.Link("Firewall Rules", "#firewall-rules"),
		markdown.Link("NAT Configuration", "#nat-configuration"),
		markdown.Link("DHCP Services", "#dhcp-services"),
		markdown.Link("DNS Resolver", "#dns-resolver"),
		markdown.Link("System Users", "#system-users"),
		markdown.Link("Services & Daemons", "#service-configuration"),
	}
	if hasTunables {
		items = append(items, markdown.Link("System Tunables", "#system-tunables"))
	}
	return items
}

// comprehensiveToCItems returns the table of contents items for a comprehensive report.
// The hasTunables parameter controls whether the "System Tunables" link is included.
func (b *MarkdownBuilder) comprehensiveToCItems(hasTunables bool) []string {
	items := []string{
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
		markdown.Link("Services & Daemons", "#service-configuration"),
	}
	if hasTunables {
		items = append(items, markdown.Link("System Tunables", "#system-tunables"))
	}
	return items
}

// BuildStandardReport builds a standard markdown report.
func (b *MarkdownBuilder) BuildStandardReport(data *common.CommonDevice) (string, error) {
	if data == nil {
		return "", ErrNilDevice
	}

	filteredSysctl := formatters.FilterSystemTunables(data.Sysctl, b.includeTunables)
	tocItems := b.standardToCItems(len(filteredSysctl) > 0)

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
		BulletList(tocItems...)

	b.writeSystemSection(md, data)
	b.writeNetworkSection(md, data)
	b.writeSecuritySection(md, data)
	b.writeServicesSection(md, data)

	if len(filteredSysctl) > 0 {
		b.WriteSysctlTable(md.H2("System Tunables"), filteredSysctl)
	}

	return md.String(), nil
}

// BuildComprehensiveReport builds a comprehensive markdown report.
func (b *MarkdownBuilder) BuildComprehensiveReport(data *common.CommonDevice) (string, error) {
	if data == nil {
		return "", ErrNilDevice
	}

	filteredSysctl := formatters.FilterSystemTunables(data.Sysctl, b.includeTunables)
	tocItems := b.comprehensiveToCItems(len(filteredSysctl) > 0)

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
		BulletList(tocItems...)

	b.writeSystemSection(md, data)
	b.writeNetworkSection(md, data)
	b.writeVLANSection(md, data)
	b.writeStaticRoutesSection(md, data)
	b.writeSecuritySection(md, data)
	b.writeIPsecSection(md, data)
	b.writeOpenVPNSection(md, data)
	b.writeHASection(md, data)
	b.writeServicesSection(md, data)

	if len(filteredSysctl) > 0 {
		b.WriteSysctlTable(md.H2("System Tunables"), filteredSysctl)
	}

	return md.String(), nil
}

// buildInterfaceDetails renders the property details for a single network interface into the markdown builder.
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
