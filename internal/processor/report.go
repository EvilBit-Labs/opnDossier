package processor

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/metrics"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/nao1215/markdown"
	"gopkg.in/yaml.v3"
)

// Report contains the results of processing an OPNsense configuration.
// It includes the normalized configuration, analysis findings, and statistics.
type Report struct {
	mu sync.RWMutex `json:"-" yaml:"-"` // protects Findings for concurrent access
	// GeneratedAt contains the timestamp when the report was generated
	GeneratedAt time.Time `json:"generatedAt"`

	// ConfigInfo contains basic information about the processed configuration
	ConfigInfo ConfigInfo `json:"configInfo"`

	// NormalizedConfig contains the processed and normalized configuration
	NormalizedConfig *model.OpnSenseDocument `json:"normalizedConfig,omitempty"`

	// Statistics contains various statistics about the configuration
	Statistics *Statistics `json:"statistics,omitempty"`

	// Findings contains analysis findings categorized by type
	Findings Findings `json:"findings"`

	// ProcessorConfig contains the configuration used during processing
	ProcessorConfig Config `json:"processorConfig"`
}

// ConfigInfo contains basic information about the processed configuration.
type ConfigInfo struct {
	// Hostname is the configured hostname of the OPNsense system
	Hostname string `json:"hostname"`
	// Domain is the configured domain name
	Domain string `json:"domain"`
	// Version is the OPNsense version (if available)
	Version string `json:"version,omitempty"`
	// Theme is the configured web UI theme
	Theme string `json:"theme,omitempty"`
}

// Statistics contains various statistics about the configuration.
type Statistics struct {
	// Interface statistics
	TotalInterfaces  int                   `json:"totalInterfaces"`
	InterfacesByType map[string]int        `json:"interfacesByType"`
	InterfaceDetails []InterfaceStatistics `json:"interfaceDetails"`

	// Firewall and NAT statistics
	TotalFirewallRules int            `json:"totalFirewallRules"`
	RulesByInterface   map[string]int `json:"rulesByInterface"`
	RulesByType        map[string]int `json:"rulesByType"`
	NATEntries         int            `json:"natEntries"`
	NATMode            string         `json:"natMode"`

	// Gateway statistics
	TotalGateways      int `json:"totalGateways"`
	TotalGatewayGroups int `json:"totalGatewayGroups"`

	// DHCP statistics
	DHCPScopes       int                   `json:"dhcpScopes"`
	DHCPScopeDetails []DHCPScopeStatistics `json:"dhcpScopeDetails"`

	// User and group statistics
	TotalUsers    int            `json:"totalUsers"`
	UsersByScope  map[string]int `json:"usersByScope"`
	TotalGroups   int            `json:"totalGroups"`
	GroupsByScope map[string]int `json:"groupsByScope"`

	// Service statistics
	EnabledServices []string            `json:"enabledServices"`
	TotalServices   int                 `json:"totalServices"`
	ServiceDetails  []ServiceStatistics `json:"serviceDetails"`

	// System configuration statistics
	SysctlSettings       int      `json:"sysctlSettings"`
	LoadBalancerMonitors int      `json:"loadBalancerMonitors"`
	SecurityFeatures     []string `json:"securityFeatures"`

	// Summary counts for quick reference
	Summary StatisticsSummary `json:"summary"`
}

// InterfaceStatistics contains detailed statistics for a single interface.
type InterfaceStatistics struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Enabled     bool   `json:"enabled"`
	HasIPv4     bool   `json:"hasIpv4"`
	HasIPv6     bool   `json:"hasIpv6"`
	HasDHCP     bool   `json:"hasDhcp"`
	BlockPriv   bool   `json:"blockPriv"`
	BlockBogons bool   `json:"blockBogons"`
}

// DHCPScopeStatistics contains statistics for DHCP scopes.
type DHCPScopeStatistics struct {
	Interface string `json:"interface"`
	Enabled   bool   `json:"enabled"`
	From      string `json:"from"`
	To        string `json:"to"`
}

// ServiceStatistics contains statistics for individual services.
type ServiceStatistics struct {
	Name    string            `json:"name"`
	Enabled bool              `json:"enabled"`
	Details map[string]string `json:"details,omitempty"`
}

// StatisticsSummary provides high-level summary statistics.
type StatisticsSummary struct {
	TotalConfigItems    int  `json:"totalConfigItems"`
	SecurityScore       int  `json:"securityScore"`
	ConfigComplexity    int  `json:"configComplexity"`
	HasSecurityFeatures bool `json:"hasSecurityFeatures"`
}

// Findings contains analysis findings categorized by severity and type.
type Findings struct {
	// Critical findings that require immediate attention
	Critical []Finding `json:"critical,omitempty"`
	// High severity findings
	High []Finding `json:"high,omitempty"`
	// Medium severity findings
	Medium []Finding `json:"medium,omitempty"`
	// Low severity findings
	Low []Finding `json:"low,omitempty"`
	// Informational findings
	Info []Finding `json:"info,omitempty"`
}

// Finding represents a single analysis finding.
type Finding struct {
	// Type categorizes the finding (e.g., "security", "performance", "compliance")
	Type string `json:"type"`
	// Title is a brief description of the finding
	Title string `json:"title"`
	// Description provides detailed information about the finding
	Description string `json:"description"`
	// Recommendation suggests how to address the finding
	Recommendation string `json:"recommendation,omitempty"`
	// Component identifies the configuration component involved
	Component string `json:"component,omitempty"`
	// Reference provides additional information or documentation links
	Reference string `json:"reference,omitempty"`
}

// Severity represents the severity levels for findings.
type Severity string

// Severity constants represent the different levels of finding severity.
const (
	// SeverityCritical represents critical findings that require immediate attention.
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// NewReport returns a new Report instance populated with configuration metadata, processor settings, and optionally generated statistics and normalized configuration data.
func NewReport(cfg *model.OpnSenseDocument, processorConfig Config) *Report {
	report := &Report{
		GeneratedAt:     time.Now().UTC(),
		ProcessorConfig: processorConfig,
		Findings: Findings{
			Critical: make([]Finding, 0),
			High:     make([]Finding, 0),
			Medium:   make([]Finding, 0),
			Low:      make([]Finding, 0),
			Info:     make([]Finding, 0),
		},
	}

	if cfg != nil {
		report.ConfigInfo = ConfigInfo{
			Hostname: cfg.Hostname(),
			Domain:   cfg.System.Domain,
			Version:  cfg.Version,
			Theme:    cfg.Theme,
		}

		if processorConfig.EnableStats {
			report.Statistics = generateStatistics(cfg)
		}

		// Store normalized config if requested (could be controlled by an option)
		report.NormalizedConfig = cfg
	}

	return report
}

// AddFinding adds a finding to the report with the specified severity.
func (r *Report) AddFinding(severity Severity, finding Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch severity {
	case SeverityCritical:
		r.Findings.Critical = append(r.Findings.Critical, finding)
	case SeverityHigh:
		r.Findings.High = append(r.Findings.High, finding)
	case SeverityMedium:
		r.Findings.Medium = append(r.Findings.Medium, finding)
	case SeverityLow:
		r.Findings.Low = append(r.Findings.Low, finding)
	case SeverityInfo:
		r.Findings.Info = append(r.Findings.Info, finding)
	}
}

// TotalFindings returns the total number of findings across all severities.
func (r *Report) TotalFindings() int {
	return len(r.Findings.Critical) + len(r.Findings.High) +
		len(r.Findings.Medium) + len(r.Findings.Low) + len(r.Findings.Info)
}

// HasCriticalFindings returns true if the report contains critical findings.
func (r *Report) HasCriticalFindings() bool {
	return len(r.Findings.Critical) > 0
}

// OutputFormat represents the supported output formats.
type OutputFormat string

const (
	// OutputFormatMarkdown outputs the report as Markdown.
	OutputFormatMarkdown OutputFormat = "markdown"
	// OutputFormatJSON outputs the report as JSON.
	OutputFormatJSON OutputFormat = "json"
	// OutputFormatYAML outputs the report as YAML.
	OutputFormatYAML OutputFormat = "yaml"
)

// ToFormat returns the report in the specified format.
func (r *Report) ToFormat(format OutputFormat) (string, error) {
	switch format {
	case OutputFormatMarkdown:
		return r.ToMarkdown(), nil
	case OutputFormatJSON:
		return r.ToJSON()
	case OutputFormatYAML:
		return r.ToYAML()
	default:
		return "", &UnsupportedFormatError{Format: string(format)}
	}
}

// ToJSON returns the report as a JSON string.
func (r *Report) ToJSON() (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	data, err := json.MarshalIndent(r, "", "  ") //nolint:musttag // Report has proper json tags
	if err != nil {
		return "", fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	return string(data), nil
}

// ToYAML returns the report as a YAML string.
func (r *Report) ToYAML() (string, error) {
	data, err := yaml.Marshal(r) //nolint:musttag // Report has proper yaml tags
	if err != nil {
		return "", fmt.Errorf("failed to marshal report to YAML: %w", err)
	}

	return string(data), nil
}

// ToMarkdown returns the report formatted as Markdown using the markdown library.
func (r *Report) ToMarkdown() string {
	var buf strings.Builder
	md := markdown.NewMarkdown(&buf)

	r.addHeader(md)
	r.addConfigInfo(md)

	if r.Statistics != nil {
		r.addStatistics(md)
	}

	r.addFindings(md)

	if err := md.Build(); err != nil {
		return "# OPNsense Configuration Analysis Report\n\nError generating report.\n"
	}

	return buf.String()
}

// Helper functions for Markdown generation

func (r *Report) addHeader(md *markdown.Markdown) {
	md.H1("OPNsense Configuration Analysis Report")
	md.PlainTextf("Generated: %s", r.GeneratedAt.Format(time.RFC3339))
	md.LF()
}

func (r *Report) addConfigInfo(md *markdown.Markdown) {
	md.H2("Configuration Information")
	configItems := []string{
		fmt.Sprintf("%s: %s", markdown.Bold("Hostname"), r.ConfigInfo.Hostname),
		fmt.Sprintf("%s: %s", markdown.Bold("Domain"), r.ConfigInfo.Domain),
	}
	if r.ConfigInfo.Version != "" {
		configItems = append(configItems, fmt.Sprintf("%s: %s", markdown.Bold("Version"), r.ConfigInfo.Version))
	}
	if r.ConfigInfo.Theme != "" {
		configItems = append(configItems, fmt.Sprintf("%s: %s", markdown.Bold("Theme"), r.ConfigInfo.Theme))
	}
	md.BulletList(configItems...)
	md.LF()
}

func (r *Report) addStatistics(md *markdown.Markdown) {
	md.H2("Configuration Statistics")
	md.H3("Overview")
	overviewItems := []string{
		fmt.Sprintf("%s: %d", markdown.Bold("Total Interfaces"), r.Statistics.TotalInterfaces),
		fmt.Sprintf("%s: %d", markdown.Bold("Firewall Rules"), r.Statistics.TotalFirewallRules),
		fmt.Sprintf("%s: %d", markdown.Bold("NAT Entries"), r.Statistics.NATEntries),
		fmt.Sprintf("%s: %d", markdown.Bold("DHCP Scopes"), r.Statistics.DHCPScopes),
		fmt.Sprintf("%s: %d", markdown.Bold("Users"), r.Statistics.TotalUsers),
		fmt.Sprintf("%s: %d", markdown.Bold("Groups"), r.Statistics.TotalGroups),
		fmt.Sprintf("%s: %d", markdown.Bold("Services"), r.Statistics.TotalServices),
		fmt.Sprintf("%s: %d", markdown.Bold("Sysctl Settings"), r.Statistics.SysctlSettings),
	}
	md.BulletList(overviewItems...)
	md.LF()

	md.H3("Summary Metrics")
	summaryItems := []string{
		fmt.Sprintf("%s: %d", markdown.Bold("Total Configuration Items"), r.Statistics.Summary.TotalConfigItems),
		fmt.Sprintf("%s: %d/100", markdown.Bold("Security Score"), r.Statistics.Summary.SecurityScore),
		fmt.Sprintf("%s: %d/100", markdown.Bold("Configuration Complexity"), r.Statistics.Summary.ConfigComplexity),
		fmt.Sprintf("%s: %t", markdown.Bold("Has Security Features"), r.Statistics.Summary.HasSecurityFeatures),
	}
	md.BulletList(summaryItems...)
	md.LF()

	addInterfaceDetails(md, "Interface Details", r.Statistics.InterfaceDetails)
	addStatisticsList(md, "Firewall Rules by Interface", r.Statistics.RulesByInterface, " rules")
	addStatisticsList(md, "Firewall Rules by Type", r.Statistics.RulesByType, " rules")
	addDHCPScopeDetails(md, "DHCP Scope Details", r.Statistics.DHCPScopeDetails)
	addStatisticsList(md, "Users by Scope", r.Statistics.UsersByScope, " users")
	addStatisticsList(md, "Groups by Scope", r.Statistics.GroupsByScope, " groups")

	if len(r.Statistics.EnabledServices) > 0 {
		md.H3("Enabled Services")
		md.BulletList(r.Statistics.EnabledServices...)
		md.LF()
	}

	if len(r.Statistics.ServiceDetails) > 0 {
		md.H3("Service Details")
		for _, service := range r.Statistics.ServiceDetails {
			md.H4(service.Name)
			serviceItems := []string{
				fmt.Sprintf("%s: %t", markdown.Bold("Enabled"), service.Enabled),
			}
			for k, v := range service.Details {
				serviceItems = append(serviceItems, fmt.Sprintf("%s: %s", markdown.Bold(k), v))
			}
			md.BulletList(serviceItems...)
			md.LF()
		}
	}

	if len(r.Statistics.SecurityFeatures) > 0 {
		md.H3("Security Features")
		md.BulletList(r.Statistics.SecurityFeatures...)
		md.LF()
	}

	if r.Statistics.NATMode != "" {
		md.H3("NAT Configuration")
		natItems := []string{
			fmt.Sprintf("%s: %s", markdown.Bold("NAT Mode"), r.Statistics.NATMode),
			fmt.Sprintf("%s: %d", markdown.Bold("NAT Entries"), r.Statistics.NATEntries),
		}
		md.BulletList(natItems...)
		md.LF()
	}

	if r.Statistics.LoadBalancerMonitors > 0 {
		md.H3("Load Balancer")
		lbItems := []string{
			fmt.Sprintf("%s: %d", markdown.Bold("Monitors"), r.Statistics.LoadBalancerMonitors),
		}
		md.BulletList(lbItems...)
		md.LF()
	}
}

func (r *Report) addFindings(md *markdown.Markdown) {
	md.H2("Analysis Findings")
	if r.TotalFindings() == 0 {
		md.PlainText("No findings to report.")
		md.LF()
		return
	}

	md.PlainText(fmt.Sprintf("Total findings: %d", r.TotalFindings()))
	md.LF()

	r.addFindingsSection(md, "Critical", r.Findings.Critical)
	r.addFindingsSection(md, "High", r.Findings.High)
	r.addFindingsSection(md, "Medium", r.Findings.Medium)
	r.addFindingsSection(md, "Low", r.Findings.Low)
	r.addFindingsSection(md, "Informational", r.Findings.Info)
}

func addStatisticsList(md *markdown.Markdown, title string, stats map[string]int, suffix string) {
	if len(stats) == 0 {
		return
	}
	md.H3(title)
	items := []string{}
	for k, v := range stats {
		items = append(items, fmt.Sprintf("%s: %d%s", markdown.Bold(k), v, suffix))
	}
	md.BulletList(items...)
	md.LF()
}

func addInterfaceDetails(md *markdown.Markdown, title string, details []InterfaceStatistics) {
	if len(details) == 0 {
		return
	}
	md.H3(title)
	table := markdown.TableSet{
		Header: []string{"Interface", "Type", "Enabled", "IPv4", "IPv6", "DHCP", "Block Private", "Block Bogons"},
		Rows:   [][]string{},
	}
	for _, detail := range details {
		table.Rows = append(table.Rows, []string{
			detail.Name,
			detail.Type,
			strconv.FormatBool(detail.Enabled),
			strconv.FormatBool(detail.HasIPv4),
			strconv.FormatBool(detail.HasIPv6),
			strconv.FormatBool(detail.HasDHCP),
			strconv.FormatBool(detail.BlockPriv),
			strconv.FormatBool(detail.BlockBogons),
		})
	}
	md.Table(table)
	md.LF()
}

func addDHCPScopeDetails(md *markdown.Markdown, title string, details []DHCPScopeStatistics) {
	if len(details) == 0 {
		return
	}
	md.H3(title)
	table := markdown.TableSet{
		Header: []string{"Interface", "Enabled", "Range Start", "Range End"},
		Rows:   [][]string{},
	}
	for _, detail := range details {
		table.Rows = append(table.Rows, []string{
			detail.Interface,
			strconv.FormatBool(detail.Enabled),
			detail.From,
			detail.To,
		})
	}
	md.Table(table)
	md.LF()
}

// Summary returns a brief summary of the report.
func (r *Report) Summary() string {
	var summary strings.Builder

	summary.WriteString("OPNsense Configuration Report for " + r.ConfigInfo.Hostname)

	if r.ConfigInfo.Domain != "" {
		summary.WriteString("." + r.ConfigInfo.Domain)
	}

	summary.WriteString("\n")

	if r.Statistics != nil {
		summary.WriteString(
			fmt.Sprintf("Configuration contains %d interfaces, %d firewall rules, %d users, and %d groups.\n",
				r.Statistics.TotalInterfaces, r.Statistics.TotalFirewallRules,
				r.Statistics.TotalUsers, r.Statistics.TotalGroups),
		)
	}

	totalFindings := r.TotalFindings()
	if totalFindings == 0 {
		summary.WriteString("No issues found in the configuration.")
	} else {
		summary.WriteString(fmt.Sprintf("Analysis found %d findings: ", totalFindings))

		parts := []string{}
		if len(r.Findings.Critical) > 0 {
			parts = append(parts, fmt.Sprintf("%d critical", len(r.Findings.Critical)))
		}

		if len(r.Findings.High) > 0 {
			parts = append(parts, fmt.Sprintf("%d high", len(r.Findings.High)))
		}

		if len(r.Findings.Medium) > 0 {
			parts = append(parts, fmt.Sprintf("%d medium", len(r.Findings.Medium)))
		}

		if len(r.Findings.Low) > 0 {
			parts = append(parts, fmt.Sprintf("%d low", len(r.Findings.Low)))
		}

		if len(r.Findings.Info) > 0 {
			parts = append(parts, fmt.Sprintf("%d info", len(r.Findings.Info)))
		}

		summary.WriteString(strings.Join(parts, ", "))
		summary.WriteString(".")
	}

	return summary.String()
}

// addFindingsSection adds a findings section using the markdown library.
func (r *Report) addFindingsSection(md *markdown.Markdown, title string, findings []Finding) {
	if len(findings) == 0 {
		return
	}

	md.H3(fmt.Sprintf("%s (%d)", title, len(findings)))

	for i, finding := range findings {
		md.H4(fmt.Sprintf("%d. %s", i+1, finding.Title))

		findingItems := []string{
			fmt.Sprintf("%s: %s", markdown.Bold("Type"), finding.Type),
		}

		if finding.Component != "" {
			findingItems = append(findingItems, fmt.Sprintf("%s: %s", markdown.Bold("Component"), finding.Component))
		}

		findingItems = append(findingItems, fmt.Sprintf("%s: %s", markdown.Bold("Description"), finding.Description))

		if finding.Recommendation != "" {
			findingItems = append(
				findingItems,
				fmt.Sprintf("%s: %s", markdown.Bold("Recommendation"), finding.Recommendation),
			)
		}

		if finding.Reference != "" {
			findingItems = append(findingItems, fmt.Sprintf("%s: %s", markdown.Bold("Reference"), finding.Reference))
		}

		md.BulletList(findingItems...)
		md.HorizontalRule()
		md.LF()
	}
}

// generateStatistics analyzes an OPNsense configuration and returns aggregated statistics.
//
// The returned Statistics struct includes interface details, firewall and NAT rule counts, DHCP scopes, user and group counts, enabled services, system settings, detected security features, and summary metrics such as total configuration items, security score, and complexity.
func generateStatistics(cfg *model.OpnSenseDocument) *Statistics {
	stats := &Statistics{
		InterfacesByType: make(map[string]int),
		InterfaceDetails: []InterfaceStatistics{},
		RulesByInterface: make(map[string]int),
		RulesByType:      make(map[string]int),
		DHCPScopeDetails: []DHCPScopeStatistics{},
		UsersByScope:     make(map[string]int),
		GroupsByScope:    make(map[string]int),
		EnabledServices:  []string{},
		ServiceDetails:   []ServiceStatistics{},
		SecurityFeatures: []string{},
	}

	// Interface statistics
	stats.TotalInterfaces = 2 // WAN and LAN are always present
	stats.InterfacesByType["wan"] = 1
	stats.InterfacesByType["lan"] = 1

	// Interface details
	wanStats := InterfaceStatistics{
		Name: "wan",
		Type: "wan",
	}
	if wanDhcp, exists := cfg.Dhcpd.Wan(); exists {
		wanStats.HasDHCP = wanDhcp.Enable != ""
	}

	if wan, ok := cfg.Interfaces.Wan(); ok {
		wanStats.Enabled = wan.Enable != ""
		wanStats.HasIPv4 = wan.IPAddr != ""
		wanStats.HasIPv6 = wan.IPAddrv6 != ""
		wanStats.BlockPriv = wan.BlockPriv != ""
		wanStats.BlockBogons = wan.BlockBogons != ""
	}

	lanStats := InterfaceStatistics{
		Name: "lan",
		Type: "lan",
	}
	if lanDhcp, exists := cfg.Dhcpd.Lan(); exists {
		lanStats.HasDHCP = lanDhcp.Enable != ""
	}

	if lan, ok := cfg.Interfaces.Lan(); ok {
		lanStats.Enabled = lan.Enable != ""
		lanStats.HasIPv4 = lan.IPAddr != ""
		lanStats.HasIPv6 = lan.IPAddrv6 != ""
		lanStats.BlockPriv = lan.BlockPriv != ""
		lanStats.BlockBogons = lan.BlockBogons != ""
	}

	stats.InterfaceDetails = append(stats.InterfaceDetails, wanStats, lanStats)

	// Firewall rule statistics
	rules := cfg.FilterRules()

	stats.TotalFirewallRules = len(rules)
	for _, rule := range rules {
		// Count each interface in the rule separately
		for _, iface := range rule.Interface {
			stats.RulesByInterface[iface]++
		}
		stats.RulesByType[rule.Type]++
	}

	// NAT statistics
	stats.NATMode = cfg.Nat.Outbound.Mode
	if cfg.Nat.Outbound.Mode != "" {
		stats.NATEntries = 1 // Count NAT configuration as present
	}

	// Gateway statistics
	stats.TotalGateways = len(cfg.Gateways.Gateway)
	stats.TotalGatewayGroups = len(cfg.Gateways.Groups)

	// DHCP statistics
	dhcpScopes := 0
	if lanDhcp, exists := cfg.Dhcpd.Lan(); exists && lanDhcp.Enable != "" {
		dhcpScopes++

		stats.DHCPScopeDetails = append(stats.DHCPScopeDetails, DHCPScopeStatistics{
			Interface: "lan",
			Enabled:   true,
			From:      lanDhcp.Range.From,
			To:        lanDhcp.Range.To,
		})
	}

	if wanDhcp, exists := cfg.Dhcpd.Wan(); exists && wanDhcp.Enable != "" {
		dhcpScopes++

		stats.DHCPScopeDetails = append(stats.DHCPScopeDetails, DHCPScopeStatistics{
			Interface: "wan",
			Enabled:   true,
			From:      wanDhcp.Range.From,
			To:        wanDhcp.Range.To,
		})
	}

	stats.DHCPScopes = dhcpScopes

	// User and group statistics
	stats.TotalUsers = len(cfg.System.User)

	stats.TotalGroups = len(cfg.System.Group)
	for _, user := range cfg.System.User {
		stats.UsersByScope[user.Scope]++
	}

	for _, group := range cfg.System.Group {
		stats.GroupsByScope[group.Scope]++
	}

	// Service statistics
	serviceCount := 0

	if lanDhcp, exists := cfg.Dhcpd.Lan(); exists && lanDhcp.Enable != "" {
		stats.EnabledServices = append(stats.EnabledServices, "DHCP Server (LAN)")
		stats.ServiceDetails = append(stats.ServiceDetails, ServiceStatistics{
			Name:    "DHCP Server (LAN)",
			Enabled: true,
			Details: map[string]string{
				"interface": "lan",
				"from":      lanDhcp.Range.From,
				"to":        lanDhcp.Range.To,
			},
		})
		serviceCount++
	}

	if wanDhcp, exists := cfg.Dhcpd.Wan(); exists && wanDhcp.Enable != "" {
		stats.EnabledServices = append(stats.EnabledServices, "DHCP Server (WAN)")
		stats.ServiceDetails = append(stats.ServiceDetails, ServiceStatistics{
			Name:    "DHCP Server (WAN)",
			Enabled: true,
			Details: map[string]string{
				"interface": "wan",
				"from":      wanDhcp.Range.From,
				"to":        wanDhcp.Range.To,
			},
		})
		serviceCount++
	}

	if cfg.Unbound.Enable != "" {
		stats.EnabledServices = append(stats.EnabledServices, "Unbound DNS Resolver")
		stats.ServiceDetails = append(stats.ServiceDetails, ServiceStatistics{
			Name:    "Unbound DNS Resolver",
			Enabled: true,
		})
		serviceCount++
	}

	if cfg.Snmpd.ROCommunity != "" {
		stats.EnabledServices = append(stats.EnabledServices, "SNMP Daemon")
		stats.ServiceDetails = append(stats.ServiceDetails, ServiceStatistics{
			Name:    "SNMP Daemon",
			Enabled: true,
			Details: map[string]string{
				"location":  cfg.Snmpd.SysLocation,
				"contact":   cfg.Snmpd.SysContact,
				"community": "[REDACTED]", // Don't expose actual community string
			},
		})
		serviceCount++
	}

	if cfg.System.SSH.Group != "" {
		stats.EnabledServices = append(stats.EnabledServices, "SSH Daemon")
		stats.ServiceDetails = append(stats.ServiceDetails, ServiceStatistics{
			Name:    "SSH Daemon",
			Enabled: true,
			Details: map[string]string{
				"group": cfg.System.SSH.Group,
			},
		})
		serviceCount++
	}

	if cfg.Ntpd.Prefer != "" {
		stats.EnabledServices = append(stats.EnabledServices, "NTP Daemon")
		stats.ServiceDetails = append(stats.ServiceDetails, ServiceStatistics{
			Name:    "NTP Daemon",
			Enabled: true,
			Details: map[string]string{
				"prefer": cfg.Ntpd.Prefer,
			},
		})
		serviceCount++
	}

	stats.TotalServices = serviceCount

	// System configuration statistics
	stats.SysctlSettings = len(cfg.Sysctl)
	stats.LoadBalancerMonitors = len(cfg.LoadBalancer.MonitorType)

	// Security features detection
	if wan, ok := cfg.Interfaces.Wan(); ok {
		if wan.BlockPriv != "" {
			stats.SecurityFeatures = append(stats.SecurityFeatures, "Block Private Networks")
		}

		if wan.BlockBogons != "" {
			stats.SecurityFeatures = append(stats.SecurityFeatures, "Block Bogon Networks")
		}
	}

	if cfg.System.WebGUI.Protocol == constants.ProtocolHTTPS {
		stats.SecurityFeatures = append(stats.SecurityFeatures, "HTTPS Web GUI")
	}

	if cfg.System.DisableNATReflection != "" {
		stats.SecurityFeatures = append(stats.SecurityFeatures, "NAT Reflection Disabled")
	}

	// Calculate summary statistics
	securityScore := calculateSecurityScore(cfg, stats)
	configComplexity := calculateConfigComplexity(stats)

	stats.Summary = StatisticsSummary{
		TotalConfigItems: metrics.CalculateTotalConfigItems(
			stats.TotalInterfaces,
			stats.TotalFirewallRules,
			stats.TotalUsers,
			stats.TotalGroups,
			stats.TotalServices,
			stats.TotalGateways,
			stats.TotalGatewayGroups,
			stats.SysctlSettings,
			stats.DHCPScopes,
			stats.LoadBalancerMonitors,
		),
		SecurityScore:       securityScore,
		ConfigComplexity:    configComplexity,
		HasSecurityFeatures: len(stats.SecurityFeatures) > 0,
	}

	return stats
}

// calculateSecurityScore returns a security score for the given OPNsense configuration based on detected security features, firewall rules, HTTPS Web GUI usage, and SSH group configuration. The score is capped at a defined maximum.
func calculateSecurityScore(cfg *model.OpnSenseDocument, stats *Statistics) int {
	score := 0

	// Security features contribute to score
	score += len(stats.SecurityFeatures) * constants.SecurityFeatureMultiplier

	// Firewall rules indicate active security configuration
	if stats.TotalFirewallRules > 0 {
		score += 20
	}

	// HTTPS web interface
	if cfg.System.WebGUI.Protocol == constants.ProtocolHTTPS {
		score += 15
	}

	// SSH configuration
	if cfg.System.SSH.Group != "" {
		score += 10
	}

	// Cap at MaxSecurityScore
	if score > constants.MaxSecurityScore {
		score = constants.MaxSecurityScore
	}

	return score
}

// calculateConfigComplexity returns a normalized complexity score for the configuration based on weighted counts of interfaces, firewall rules, users, groups, sysctl settings, services, DHCP scopes, and load balancer monitors. The score is scaled to a maximum defined value.
func calculateConfigComplexity(stats *Statistics) int {
	complexity := 0

	// Each configuration type adds to complexity
	complexity += stats.TotalInterfaces * constants.InterfaceComplexityWeight
	complexity += stats.TotalFirewallRules * constants.FirewallRuleComplexityWeight
	complexity += stats.TotalUsers * constants.UserComplexityWeight
	complexity += stats.TotalGroups * constants.GroupComplexityWeight
	complexity += stats.SysctlSettings * constants.SysctlComplexityWeight
	complexity += stats.TotalServices * constants.ServiceComplexityWeight
	complexity += stats.DHCPScopes * constants.DHCPComplexityWeight
	complexity += stats.LoadBalancerMonitors * constants.LoadBalancerComplexityWeight
	complexity += stats.TotalGateways * constants.GatewayComplexityWeight
	complexity += stats.TotalGatewayGroups * constants.GatewayGroupComplexityWeight

	// Normalize to 0-100 scale (assuming max reasonable config)
	normalizedComplexity := min(
		(complexity*constants.MaxComplexityScore)/constants.MaxReasonableComplexity,
		constants.MaxComplexityScore,
	)

	return normalizedComplexity
}
