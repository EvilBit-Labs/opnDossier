package processor

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/enrichment"
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

	// IDS/IPS statistics
	IDSEnabled             bool     `json:"idsEnabled"`
	IDSMode                string   `json:"idsMode"`
	IDSMonitoredInterfaces []string `json:"idsMonitoredInterfaces,omitempty"`
	IDSDetectionProfile    string   `json:"idsDetectionProfile,omitempty"`
	IDSLoggingEnabled      bool     `json:"idsLoggingEnabled"`

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
	// SeverityHigh represents high-severity findings that should be addressed soon.
	SeverityHigh Severity = "high"
	// SeverityMedium represents medium-severity findings worth investigating.
	SeverityMedium Severity = "medium"
	// SeverityLow represents low-severity findings for general improvement.
	SeverityLow Severity = "low"
	// SeverityInfo represents informational findings with no immediate action required.
	SeverityInfo Severity = "info"
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
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.totalFindingsUnsafe()
}

// totalFindingsUnsafe returns total findings without locking. Caller must hold mu.
func (r *Report) totalFindingsUnsafe() int {
	return len(r.Findings.Critical) + len(r.Findings.High) +
		len(r.Findings.Medium) + len(r.Findings.Low) + len(r.Findings.Info)
}

// HasCriticalFindings returns true if the report contains critical findings.
func (r *Report) HasCriticalFindings() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
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
	r.mu.RLock()
	defer r.mu.RUnlock()
	data, err := yaml.Marshal(r) //nolint:musttag // Report has proper yaml tags
	if err != nil {
		return "", fmt.Errorf("failed to marshal report to YAML: %w", err)
	}

	return string(data), nil
}

// ToMarkdown returns the report formatted as Markdown using the markdown library.
func (r *Report) ToMarkdown() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var buf strings.Builder
	md := markdown.NewMarkdown(&buf)

	r.addHeader(md)
	r.addConfigInfo(md)

	if r.Statistics != nil {
		r.addStatistics(md)
	}

	r.addFindingsUnsafe(md)

	if err := md.Build(); err != nil {
		return "# OPNsense Configuration Analysis Report\n\nError generating report.\n"
	}

	return buf.String()
}

// Helper functions for Markdown generation

func (r *Report) addHeader(md *markdown.Markdown) {
	md.H1("OPNsense Configuration Analysis Report").
		PlainTextf("Generated: %s", r.GeneratedAt.Format(time.RFC3339)).
		LF()
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

	summaryItems := []string{
		fmt.Sprintf("%s: %d", markdown.Bold("Total Configuration Items"), r.Statistics.Summary.TotalConfigItems),
		fmt.Sprintf("%s: %d/100", markdown.Bold("Security Score"), r.Statistics.Summary.SecurityScore),
		fmt.Sprintf("%s: %d/100", markdown.Bold("Configuration Complexity"), r.Statistics.Summary.ConfigComplexity),
		fmt.Sprintf("%s: %t", markdown.Bold("Has Security Features"), r.Statistics.Summary.HasSecurityFeatures),
	}

	md.
		H2("Configuration Statistics").
		H3("Overview").
		BulletList(overviewItems...).
		LF().
		H3("Summary Metrics").
		BulletList(summaryItems...).
		LF()

	addInterfaceDetails(md, "Interface Details", r.Statistics.InterfaceDetails)
	addStatisticsList(md, "Firewall Rules by Interface", r.Statistics.RulesByInterface, " rules")
	addStatisticsList(md, "Firewall Rules by Type", r.Statistics.RulesByType, " rules")
	addDHCPScopeDetails(md, "DHCP Scope Details", r.Statistics.DHCPScopeDetails)
	addStatisticsList(md, "Users by Scope", r.Statistics.UsersByScope, " users")
	addStatisticsList(md, "Groups by Scope", r.Statistics.GroupsByScope, " groups")

	if len(r.Statistics.EnabledServices) > 0 {
		md.H3("Enabled Services").
			BulletList(r.Statistics.EnabledServices...).
			LF()
	}

	if len(r.Statistics.ServiceDetails) > 0 {
		md.H3("Service Details")
		for _, service := range r.Statistics.ServiceDetails {
			serviceItems := []string{
				fmt.Sprintf("%s: %t", markdown.Bold("Enabled"), service.Enabled),
			}
			// Sort detail keys for deterministic output
			detailKeys := slices.Sorted(maps.Keys(service.Details))
			for _, k := range detailKeys {
				serviceItems = append(serviceItems, fmt.Sprintf("%s: %s", markdown.Bold(k), service.Details[k]))
			}

			md.
				H4(service.Name).
				BulletList(serviceItems...).
				LF()
		}
	}

	if len(r.Statistics.SecurityFeatures) > 0 {
		md.
			H3("Security Features").
			BulletList(r.Statistics.SecurityFeatures...).
			LF()
	}

	if r.Statistics.NATMode != "" {
		natItems := []string{
			fmt.Sprintf("%s: %s", markdown.Bold("NAT Mode"), r.Statistics.NATMode),
			fmt.Sprintf("%s: %d", markdown.Bold("NAT Entries"), r.Statistics.NATEntries),
		}
		md.
			H3("NAT Configuration").
			BulletList(natItems...).
			LF()
	}

	if r.Statistics.LoadBalancerMonitors > 0 {
		lbItems := []string{
			fmt.Sprintf("%s: %d", markdown.Bold("Monitors"), r.Statistics.LoadBalancerMonitors),
		}
		md.
			H3("Load Balancer").
			BulletList(lbItems...).
			LF()
	}

	if r.Statistics.IDSEnabled {
		idsItems := []string{
			markdown.Bold("Status") + ": Enabled",
			fmt.Sprintf("%s: %s", markdown.Bold("Mode"), r.Statistics.IDSMode),
		}
		if len(r.Statistics.IDSMonitoredInterfaces) > 0 {
			idsItems = append(idsItems, fmt.Sprintf("%s: %s",
				markdown.Bold("Monitored Interfaces"),
				strings.Join(r.Statistics.IDSMonitoredInterfaces, ", ")))
		}
		if r.Statistics.IDSDetectionProfile != "" {
			idsItems = append(idsItems, fmt.Sprintf("%s: %s",
				markdown.Bold("Detection Profile"), r.Statistics.IDSDetectionProfile))
		}
		idsItems = append(idsItems, fmt.Sprintf("%s: %t",
			markdown.Bold("Logging Enabled"), r.Statistics.IDSLoggingEnabled))

		md.
			H3("IDS/IPS Configuration").
			BulletList(idsItems...).
			LF()
	}
}

// addFindingsUnsafe adds findings to markdown. Caller must hold mu.
func (r *Report) addFindingsUnsafe(md *markdown.Markdown) {
	md.H2("Analysis Findings")
	if r.totalFindingsUnsafe() == 0 {
		md.
			PlainText("No findings to report.").
			LF()
		return
	}

	md.
		PlainText(fmt.Sprintf("Total findings: %d", r.totalFindingsUnsafe())).
		LF()

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
	// Sort keys for deterministic output
	keys := slices.Sorted(maps.Keys(stats))
	items := make([]string, 0, len(keys))
	for _, k := range keys {
		items = append(items, fmt.Sprintf("%s: %d%s", markdown.Bold(k), stats[k], suffix))
	}
	md.
		H3(title).
		BulletList(items...).
		LF()
}

func addInterfaceDetails(md *markdown.Markdown, title string, details []InterfaceStatistics) {
	if len(details) == 0 {
		return
	}
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

	md.
		H3(title).
		Table(table).
		LF()
}

func addDHCPScopeDetails(md *markdown.Markdown, title string, details []DHCPScopeStatistics) {
	if len(details) == 0 {
		return
	}
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
	md.
		H3(title).
		Table(table).
		LF()
}

// Summary returns a brief summary of the report.
func (r *Report) Summary() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var buf strings.Builder
	md := markdown.NewMarkdown(&buf)

	// Title with hostname
	hostname := r.ConfigInfo.Hostname
	if r.ConfigInfo.Domain != "" {
		hostname += "." + r.ConfigInfo.Domain
	}
	md.
		PlainText("OPNsense Configuration Report for " + hostname).
		LF()

	// Configuration statistics
	if r.Statistics != nil {
		md.
			PlainTextf("Configuration contains %d interfaces, %d firewall rules, %d users, and %d groups.",
				r.Statistics.TotalInterfaces,
				r.Statistics.TotalFirewallRules,
				r.Statistics.TotalUsers,
				r.Statistics.TotalGroups).
			LF()
	}

	// Findings summary
	totalFindings := r.totalFindingsUnsafe()
	if totalFindings == 0 {
		md.PlainText("No issues found in the configuration.")
	} else {
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

		md.PlainTextf("Analysis found %d findings: %s.", totalFindings, strings.Join(parts, ", "))
	}

	if err := md.Build(); err != nil {
		return fmt.Sprintf("Error generating summary: %v", err)
	}

	return buf.String()
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

		md.
			BulletList(findingItems...).
			HorizontalRule().
			LF()
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

	// IDS/IPS statistics
	// Note: IDS/IPS entries are NOT added to SecurityFeatures to avoid
	// double-counting in calculateSecurityScore, which applies explicit
	// +15 (IDS) and +10 (IPS) bonuses separately.
	ids := cfg.OPNsense.IntrusionDetectionSystem
	if ids != nil && ids.IsEnabled() {
		stats.IDSEnabled = true
		stats.IDSMonitoredInterfaces = ids.GetMonitoredInterfaces()
		stats.IDSDetectionProfile = ids.General.Detect.Profile
		stats.IDSLoggingEnabled = ids.IsSyslogEnabled() || ids.IsSyslogEveEnabled()

		if ids.IsIPSMode() {
			stats.IDSMode = "IPS (Prevention)"
		} else {
			stats.IDSMode = "IDS (Detection Only)"
		}
	}

	// Calculate summary statistics
	securityScore := calculateSecurityScore(cfg, stats)
	configComplexity := calculateConfigComplexity(stats)

	stats.Summary = StatisticsSummary{
		TotalConfigItems: enrichment.CalculateTotalConfigItems(enrichment.ConfigItemCounts{
			Interfaces:     stats.TotalInterfaces,
			FirewallRules:  stats.TotalFirewallRules,
			Users:          stats.TotalUsers,
			Groups:         stats.TotalGroups,
			Services:       stats.TotalServices,
			Gateways:       stats.TotalGateways,
			GatewayGroups:  stats.TotalGatewayGroups,
			SysctlSettings: stats.SysctlSettings,
			DHCPScopes:     stats.DHCPScopes,
			LBMonitors:     stats.LoadBalancerMonitors,
		}),
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

	// IDS/IPS configuration
	if cfg.OPNsense.IntrusionDetectionSystem != nil && cfg.OPNsense.IntrusionDetectionSystem.IsEnabled() {
		score += 15
		if cfg.OPNsense.IntrusionDetectionSystem.IsIPSMode() {
			score += 10
		}
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
