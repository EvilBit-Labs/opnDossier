// Package builder provides programmatic report building functionality for device configurations.
package builder

import (
	"bytes"
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

// findingTypeInventory is the Type value for informational inventory findings
// that are rendered in "Configuration Notes" rather than "Security Findings".
const findingTypeInventory = "inventory"

// SectionBuilder defines methods for building individual report sections.
// Each method renders a specific configuration domain into a markdown string
// or returns an empty string when the section has no data.
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
// SetIncludeTunables and SetFailuresOnly configure rendering behavior before composition.
type ReportComposer interface {
	// SetIncludeTunables configures whether all system tunables are included in the report.
	// When false, only tunables matching the security prefixes used by
	// formatters.FilterSystemTunables are shown.
	SetIncludeTunables(v bool)
	// SetFailuresOnly configures whether only non-compliant controls are shown in audit reports.
	SetFailuresOnly(v bool)
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

// Compile-time assertions that MarkdownBuilder satisfies all interfaces.
var (
	_ SectionBuilder = (*MarkdownBuilder)(nil)
	_ TableWriter    = (*MarkdownBuilder)(nil)
	_ ReportComposer = (*MarkdownBuilder)(nil)
	_ ReportBuilder  = (*MarkdownBuilder)(nil)
)

// MarkdownBuilder implements the ReportBuilder interface with comprehensive
// programmatic markdown generation capabilities.
// MarkdownBuilder is not safe for concurrent use. Create a new instance per goroutine.
type MarkdownBuilder struct {
	config          *common.CommonDevice
	logger          *logging.Logger
	generated       time.Time
	toolVersion     string
	includeTunables bool
	failuresOnly    bool
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

// SetFailuresOnly configures whether only non-compliant controls are shown in audit reports.
// When true, passing controls are filtered out of the plugin results table.
// Not safe for concurrent use — call in the same goroutine as Build/Write methods.
func (b *MarkdownBuilder) SetFailuresOnly(v bool) {
	b.failuresOnly = v
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

	platformName := data.DeviceType.DisplayName()

	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf).
		H1(platformName+" Configuration Summary").
		H2("System Information").
		BulletList(
			markdown.Bold("Hostname")+": "+data.System.Hostname,
			markdown.Bold("Domain")+": "+data.System.Domain,
			markdown.Bold("Platform")+": "+strings.TrimSpace(platformName+" "+data.System.Firmware.Version),
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

	platformName := data.DeviceType.DisplayName()

	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf).
		H1(platformName+" Configuration Summary").
		H2("System Information").
		BulletList(
			markdown.Bold("Hostname")+": "+data.System.Hostname,
			markdown.Bold("Domain")+": "+data.System.Domain,
			markdown.Bold("Platform")+": "+strings.TrimSpace(platformName+" "+data.System.Firmware.Version),
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
