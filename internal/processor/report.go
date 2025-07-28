package processor

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nao1215/markdown"
	"github.com/unclesp1d3r/opnFocus/internal/constants"
	mdhelper "github.com/unclesp1d3r/opnFocus/internal/markdown"
	"github.com/unclesp1d3r/opnFocus/internal/model"
	"gopkg.in/yaml.v3"
)

// Report contains the results of processing an OPNsense configuration.
// It includes the normalized configuration, analysis findings, and statistics.
type Report struct {
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

// NewReport creates a new Report with the given configuration and processor config.
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
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal report to JSON: %w", err)
	}
	return string(data), nil
}

// ToYAML returns the report as a YAML string.
func (r *Report) ToYAML() (string, error) {
	data, err := yaml.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("failed to marshal report to YAML: %w", err)
	}
	return string(data), nil
}

// ToMarkdown returns the report formatted as Markdown using the markdown library.
func (r *Report) ToMarkdown() string {
	var buf strings.Builder
	md := markdown.NewMarkdown(&buf)

	// Title and generation info
	md.H1("OPNsense Configuration Analysis Report")
	md.PlainTextf("Generated: %s", r.GeneratedAt.Format(time.RFC3339))
	md.LF()

	// Configuration Information
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

	// Statistics
	if r.Statistics != nil {
		md.H2("Configuration Statistics")

		// Overview
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

		// Summary scores
		md.H3("Summary Metrics")
		summaryItems := []string{
			fmt.Sprintf("%s: %d", markdown.Bold("Total Configuration Items"), r.Statistics.Summary.TotalConfigItems),
			fmt.Sprintf("%s: %d/100", markdown.Bold("Security Score"), r.Statistics.Summary.SecurityScore),
			fmt.Sprintf("%s: %d/100", markdown.Bold("Configuration Complexity"), r.Statistics.Summary.ConfigComplexity),
			fmt.Sprintf("%s: %t", markdown.Bold("Has Security Features"), r.Statistics.Summary.HasSecurityFeatures),
		}
		md.BulletList(summaryItems...)
		md.LF()

		// Interface details
		if len(r.Statistics.InterfaceDetails) > 0 {
			md.H3("Interface Details")
			interfaceTable := markdown.TableSet{
				Header: []string{"Interface", "Type", "Enabled", "IPv4", "IPv6", "DHCP", "Block Private", "Block Bogons"},
				Rows:   [][]string{},
			}
			for _, iface := range r.Statistics.InterfaceDetails {
				interfaceTable.Rows = append(interfaceTable.Rows, []string{
					iface.Name,
					iface.Type,
					strconv.FormatBool(iface.Enabled),
					strconv.FormatBool(iface.HasIPv4),
					strconv.FormatBool(iface.HasIPv6),
					strconv.FormatBool(iface.HasDHCP),
					strconv.FormatBool(iface.BlockPriv),
					strconv.FormatBool(iface.BlockBogons),
				})
			}
			md.Table(interfaceTable)
			md.LF()
		}

		// Rules by interface
		if len(r.Statistics.RulesByInterface) > 0 {
			md.H3("Firewall Rules by Interface")
			rulesByIfaceItems := []string{}
			for iface, count := range r.Statistics.RulesByInterface {
				rulesByIfaceItems = append(rulesByIfaceItems, fmt.Sprintf("%s: %d rules", markdown.Bold(iface), count))
			}
			md.BulletList(rulesByIfaceItems...)
			md.LF()
		}

		// Rules by type
		if len(r.Statistics.RulesByType) > 0 {
			md.H3("Firewall Rules by Type")
			rulesByTypeItems := []string{}
			for ruleType, count := range r.Statistics.RulesByType {
				rulesByTypeItems = append(rulesByTypeItems, fmt.Sprintf("%s: %d rules", markdown.Bold(ruleType), count))
			}
			md.BulletList(rulesByTypeItems...)
			md.LF()
		}

		// DHCP scope details
		if len(r.Statistics.DHCPScopeDetails) > 0 {
			md.H3("DHCP Scope Details")
			dhcpTable := markdown.TableSet{
				Header: []string{"Interface", "Enabled", "Range Start", "Range End"},
				Rows:   [][]string{},
			}
			for _, scope := range r.Statistics.DHCPScopeDetails {
				dhcpTable.Rows = append(dhcpTable.Rows, []string{
					scope.Interface,
					strconv.FormatBool(scope.Enabled),
					scope.From,
					scope.To,
				})
			}
			md.Table(dhcpTable)
			md.LF()
		}

		// User statistics by scope
		if len(r.Statistics.UsersByScope) > 0 {
			md.H3("Users by Scope")
			userItems := []string{}
			for scope, count := range r.Statistics.UsersByScope {
				userItems = append(userItems, fmt.Sprintf("%s: %d users", markdown.Bold(scope), count))
			}
			md.BulletList(userItems...)
			md.LF()
		}

		// Group statistics by scope
		if len(r.Statistics.GroupsByScope) > 0 {
			md.H3("Groups by Scope")
			groupItems := []string{}
			for scope, count := range r.Statistics.GroupsByScope {
				groupItems = append(groupItems, fmt.Sprintf("%s: %d groups", markdown.Bold(scope), count))
			}
			md.BulletList(groupItems...)
			md.LF()
		}

		// Enabled services
		if len(r.Statistics.EnabledServices) > 0 {
			md.H3("Enabled Services")
			md.BulletList(r.Statistics.EnabledServices...)
			md.LF()
		}

		// Service details
		if len(r.Statistics.ServiceDetails) > 0 {
			md.H3("Service Details")
			for _, service := range r.Statistics.ServiceDetails {
				md.H4(service.Name)
				serviceItems := []string{
					fmt.Sprintf("%s: %t", markdown.Bold("Enabled"), service.Enabled),
				}
				if len(service.Details) > 0 {
					for key, value := range service.Details {
						serviceItems = append(serviceItems, fmt.Sprintf("%s: %s", markdown.Bold(key), value))
					}
				}
				md.BulletList(serviceItems...)
				md.LF()
			}
		}

		// Security features
		if len(r.Statistics.SecurityFeatures) > 0 {
			md.H3("Security Features")
			md.BulletList(r.Statistics.SecurityFeatures...)
			md.LF()
		}

		// NAT information
		if r.Statistics.NATMode != "" {
			md.H3("NAT Configuration")
			natItems := []string{
				fmt.Sprintf("%s: %s", markdown.Bold("NAT Mode"), r.Statistics.NATMode),
				fmt.Sprintf("%s: %d", markdown.Bold("NAT Entries"), r.Statistics.NATEntries),
			}
			md.BulletList(natItems...)
			md.LF()
		}

		// Load balancer information
		if r.Statistics.LoadBalancerMonitors > 0 {
			md.H3("Load Balancer")
			lbItems := []string{
				fmt.Sprintf("%s: %d", markdown.Bold("Monitors"), r.Statistics.LoadBalancerMonitors),
			}
			md.BulletList(lbItems...)
			md.LF()
		}
	}

	// Findings
	md.H2("Analysis Findings")

	if r.TotalFindings() == 0 {
		md.PlainText("No findings to report.")
		md.LF()
		// Build and return the markdown string
		if err := md.Build(); err != nil {
			// If build fails, return basic markdown manually
			return "# OPNsense Configuration Analysis Report\n\nNo findings to report.\n"
		}
		return buf.String()
	}

	md.PlainText(fmt.Sprintf("Total findings: %d", r.TotalFindings()))
	md.LF()

	r.addFindingsSection(md, "Critical", r.Findings.Critical)
	r.addFindingsSection(md, "High", r.Findings.High)
	r.addFindingsSection(md, "Medium", r.Findings.Medium)
	r.addFindingsSection(md, "Low", r.Findings.Low)
	r.addFindingsSection(md, "Informational", r.Findings.Info)

	// Build and return the markdown string
	if err := md.Build(); err != nil {
		// If build fails, return basic markdown manually
		return "# OPNsense Configuration Analysis Report\n\nError generating report.\n"
	}
	return buf.String()
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
		summary.WriteString(fmt.Sprintf("Configuration contains %d interfaces, %d firewall rules, %d users, and %d groups.\n",
			r.Statistics.TotalInterfaces, r.Statistics.TotalFirewallRules,
			r.Statistics.TotalUsers, r.Statistics.TotalGroups))
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
			findingItems = append(findingItems, fmt.Sprintf("%s: %s", markdown.Bold("Recommendation"), finding.Recommendation))
		}

		if finding.Reference != "" {
			findingItems = append(findingItems, fmt.Sprintf("%s: %s", markdown.Bold("Reference"), finding.Reference))
		}

		md.BulletList(findingItems...)
		md.HorizontalRule()
		md.LF()
	}
}

// generateStatistics creates statistics from the given OPNsense configuration.
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
		stats.RulesByInterface[rule.Interface]++
		stats.RulesByType[rule.Type]++
	}

	// NAT statistics
	stats.NATMode = cfg.Nat.Outbound.Mode
	if cfg.Nat.Outbound.Mode != "" {
		stats.NATEntries = 1 // Count NAT configuration as present
	}

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
	if cfg.System.Webgui.Protocol == ProtocolHTTPS {
		stats.SecurityFeatures = append(stats.SecurityFeatures, "HTTPS Web GUI")
	}
	if cfg.System.DisableNATReflection != "" {
		stats.SecurityFeatures = append(stats.SecurityFeatures, "NAT Reflection Disabled")
	}

	// Calculate summary statistics
	totalConfigItems := stats.TotalInterfaces + stats.TotalFirewallRules +
		stats.TotalUsers + stats.TotalGroups + stats.SysctlSettings +
		stats.TotalServices + stats.DHCPScopes + stats.LoadBalancerMonitors

	securityScore := calculateSecurityScore(cfg, stats)
	configComplexity := calculateConfigComplexity(stats)

	stats.Summary = StatisticsSummary{
		TotalConfigItems:    totalConfigItems,
		SecurityScore:       securityScore,
		ConfigComplexity:    configComplexity,
		HasSecurityFeatures: len(stats.SecurityFeatures) > 0,
	}

	return stats
}

// calculateSecurityScore computes a security score based on security features and configuration.
func calculateSecurityScore(cfg *model.OpnSenseDocument, stats *Statistics) int {
	score := 0

	// Security features contribute to score
	score += len(stats.SecurityFeatures) * constants.SecurityFeatureMultiplier

	// Firewall rules indicate active security configuration
	if stats.TotalFirewallRules > 0 {
		score += 20
	}

	// HTTPS web interface
	if cfg.System.Webgui.Protocol == ProtocolHTTPS {
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

// calculateConfigComplexity computes a complexity score based on configuration items.
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

	// Normalize to 0-100 scale (assuming max reasonable config)
	normalizedComplexity := (complexity * constants.MaxComplexityScore) / constants.MaxReasonableComplexity
	if normalizedComplexity > constants.MaxComplexityScore {
		normalizedComplexity = constants.MaxComplexityScore
	}

	return normalizedComplexity
}

// Configuration builders that use the common helper to emit tables/lists consistently

// BuildNetworkConfig builds a comprehensive network configuration report.
func BuildNetworkConfig(cfg *model.OpnSenseDocument) string {
	if cfg == nil {
		return NoConfigAvailable
	}

	netConfig := cfg.NetworkConfig()
	var buf strings.Builder

	buf.WriteString("## Network Configuration\n\n")

	// Interfaces section
	buf.WriteString("### Interfaces\n\n")
	if len(netConfig.Interfaces.Items) == 0 {
		buf.WriteString("*No interfaces configured*\n\n")
	} else {
		// Create interface table
		headers := []string{"Interface", "Physical", "Enabled", "IP Address", "Subnet", "IPv6", "Gateway", "MTU"}
		rows := [][]string{}

		for name, iface := range netConfig.Interfaces.Items {
			enabled := StatusNotEnabled
			if iface.Enable != "" {
				enabled = StatusEnabled
			}

			row := []string{
				name,
				iface.If,
				enabled,
				iface.IPAddr,
				iface.Subnet,
				iface.IPAddrv6,
				iface.Gateway,
				iface.MTU,
			}
			rows = append(rows, row)
		}

		buf.WriteString(mdhelper.Table(headers, rows))
		buf.WriteString("\n\n")
	}

	// Interface security settings
	buf.WriteString("### Interface Security\n\n")
	securityHeaders := []string{"Interface", "Block Private", "Block Bogons", "DHCP Hostname"}
	securityRows := [][]string{}

	for name, iface := range netConfig.Interfaces.Items {
		blockPriv := StatusNotEnabled
		if iface.BlockPriv != "" {
			blockPriv = StatusEnabled
		}

		blockBogons := StatusNotEnabled
		if iface.BlockBogons != "" {
			blockBogons = StatusEnabled
		}

		row := []string{
			name,
			blockPriv,
			blockBogons,
			iface.DHCPHostname,
		}
		securityRows = append(securityRows, row)
	}

	if len(securityRows) > 0 {
		buf.WriteString(mdhelper.Table(securityHeaders, securityRows))
		buf.WriteString("\n\n")
	} else {
		buf.WriteString("*No interface security settings configured*\n\n")
	}

	// TODO: Add VLANs and Gateways sections when model supports them
	buf.WriteString("### VLANs\n\n*VLAN configuration not available in current model*\n\n")
	buf.WriteString("### Gateways\n\n*Gateway configuration not available in current model*\n\n")

	return buf.String()
}

// BuildSecurityConfig builds a comprehensive security configuration report.
func BuildSecurityConfig(cfg *model.OpnSenseDocument) string {
	if cfg == nil {
		return NoConfigAvailable
	}

	secConfig := cfg.SecurityConfig()
	var buf strings.Builder

	buf.WriteString("## Security Configuration\n\n")

	// Firewall Rules section
	buf.WriteString("### Firewall Rules\n\n")
	if len(secConfig.Filter.Rule) == 0 {
		buf.WriteString("*No firewall rules configured*\n\n")
	} else {
		// Create rules table
		headers := []string{"#", "Action", "Protocol", "Interface", "Source", "Destination", "Description"}
		rows := [][]string{}

		for i, rule := range secConfig.Filter.Rule {
			source := rule.Source.Network
			if source == "" {
				source = NetworkAny
			}

			dest := rule.Destination.Network
			if dest == "" {
				dest = constants.NetworkAny
			}

			row := []string{
				strconv.Itoa(i + 1),
				rule.Type,
				rule.IPProtocol,
				rule.Interface,
				source,
				dest,
				rule.Descr,
			}
			rows = append(rows, row)
		}

		buf.WriteString(mdhelper.Table(headers, rows))
		buf.WriteString("\n\n")
	}

	// NAT Configuration section
	buf.WriteString("### NAT Configuration\n\n")
	if secConfig.Nat.Outbound.Mode != "" {
		natItems := []string{
			"**Outbound Mode**: " + secConfig.Nat.Outbound.Mode,
		}
		buf.WriteString(strings.Join(natItems, "\n"))
		buf.WriteString("\n\n")
	} else {
		buf.WriteString("*No NAT configuration found*\n\n")
	}

	// Security features summary
	buf.WriteString("### Security Features\n\n")
	securityFeatures := []string{}

	// Check for enabled security features
	if wan, ok := cfg.Interfaces.Wan(); ok {
		if wan.BlockPriv != "" {
			securityFeatures = append(securityFeatures, "🔒 Block Private Networks (WAN)")
		}
		if wan.BlockBogons != "" {
			securityFeatures = append(securityFeatures, "🔒 Block Bogon Networks (WAN)")
		}
	}

	if cfg.System.Webgui.Protocol == "https" {
		securityFeatures = append(securityFeatures, "🔒 HTTPS Web Interface")
	}

	if len(secConfig.Filter.Rule) > 0 {
		securityFeatures = append(securityFeatures, fmt.Sprintf("🔥 %d Firewall Rules Configured", len(secConfig.Filter.Rule)))
	}

	if len(securityFeatures) > 0 {
		for _, feature := range securityFeatures {
			buf.WriteString(fmt.Sprintf("- %s\n", feature))
		}
		buf.WriteString("\n")
	} else {
		buf.WriteString("*No security features detected*\n\n")
	}

	// TODO: Add sections for Aliases, IDS/IPS, VPNs when model supports them
	buf.WriteString("### Firewall Aliases\n\n*Alias configuration not available in current model*\n\n")
	buf.WriteString("### IDS/IPS\n\n*IDS/IPS configuration not available in current model*\n\n")
	buf.WriteString("### VPNs\n\n*VPN configuration not available in current model*\n\n")

	return buf.String()
}

// BuildServiceConfig builds a comprehensive service configuration report.
func BuildServiceConfig(cfg *model.OpnSenseDocument) string {
	if cfg == nil {
		return "*No configuration available*"
	}

	svcConfig := cfg.ServiceConfig()
	var buf strings.Builder

	buf.WriteString("## Service Configuration\n\n")

	// DHCP Services section
	buf.WriteString("### DHCP Services\n\n")
	if len(svcConfig.Dhcpd.Items) == 0 {
		buf.WriteString("*No DHCP services configured*\n\n")
	} else {
		// Create DHCP table
		headers := []string{"Interface", "Enabled", "Range Start", "Range End"}
		rows := [][]string{}

		for name, dhcp := range svcConfig.Dhcpd.Items {
			enabled := "❌"
			if dhcp.Enable != "" {
				enabled = "✅"
			}

			row := []string{
				name,
				enabled,
				dhcp.Range.From,
				dhcp.Range.To,
			}
			rows = append(rows, row)
		}

		buf.WriteString(mdhelper.Table(headers, rows))
		buf.WriteString("\n\n")
	}

	// DNS Resolver (Unbound) section
	buf.WriteString("### DNS Resolver (Unbound)\n\n")
	if svcConfig.Unbound.Enable != "" {
		buf.WriteString("✅ **Status**: Enabled\n\n")
	} else {
		buf.WriteString("❌ **Status**: Disabled\n\n")
	}

	// SNMP Service section
	buf.WriteString("### SNMP Service\n\n")
	if svcConfig.Snmpd.ROCommunity != "" {
		snmpItems := []string{
			"✅ **Status**: Enabled",
			"**System Location**: " + svcConfig.Snmpd.SysLocation,
			"**System Contact**: " + svcConfig.Snmpd.SysContact,
			"**RO Community**: [REDACTED]",
		}
		buf.WriteString(strings.Join(snmpItems, "\n"))
		buf.WriteString("\n\n")
	} else {
		buf.WriteString("❌ **Status**: Disabled\n\n")
	}

	// SSH Service section
	buf.WriteString("### SSH Service\n\n")
	if svcConfig.SSH.Group != "" {
		sshItems := []string{
			"✅ **Status**: Enabled",
			"**Allowed Group**: " + svcConfig.SSH.Group,
		}
		buf.WriteString(strings.Join(sshItems, "\n"))
		buf.WriteString("\n\n")
	} else {
		buf.WriteString("❌ **Status**: Disabled\n\n")
	}

	// NTP Service section
	buf.WriteString("### NTP Service\n\n")
	if svcConfig.Ntpd.Prefer != "" {
		ntpItems := []string{
			"✅ **Status**: Enabled",
			"**Preferred Server**: " + svcConfig.Ntpd.Prefer,
		}
		buf.WriteString(strings.Join(ntpItems, "\n"))
		buf.WriteString("\n\n")
	} else {
		buf.WriteString("❌ **Status**: Disabled\n\n")
	}

	// Load Balancer section
	buf.WriteString("### Load Balancer\n\n")
	if len(svcConfig.LoadBalancer.MonitorType) == 0 {
		buf.WriteString("*No load balancer monitors configured*\n\n")
	} else {
		// Create load balancer table
		headers := []string{"Monitor Name", "Type", "Description"}
		rows := [][]string{}

		for _, monitor := range svcConfig.LoadBalancer.MonitorType {
			row := []string{
				monitor.Name,
				monitor.Type,
				monitor.Descr,
			}
			rows = append(rows, row)
		}

		buf.WriteString(mdhelper.Table(headers, rows))
		buf.WriteString("\n\n")
	}

	// RRD Service section
	buf.WriteString("### RRD (Monitoring)\n\n")
	// Check if RRD is enabled (struct{} means enabled in OPNsense XML)
	buf.WriteString("✅ **Status**: Enabled (default)\n\n")

	// Service summary
	buf.WriteString("### Service Summary\n\n")
	enabledCount := 0
	totalServices := 5 // Base services we check for

	serviceStatus := []string{}
	if svcConfig.Unbound.Enable != "" {
		enabledCount++
		serviceStatus = append(serviceStatus, "✅ DNS Resolver")
	} else {
		serviceStatus = append(serviceStatus, "❌ DNS Resolver")
	}

	if svcConfig.Snmpd.ROCommunity != "" {
		enabledCount++
		serviceStatus = append(serviceStatus, "✅ SNMP")
	} else {
		serviceStatus = append(serviceStatus, "❌ SNMP")
	}

	if svcConfig.SSH.Group != "" {
		enabledCount++
		serviceStatus = append(serviceStatus, "✅ SSH")
	} else {
		serviceStatus = append(serviceStatus, "❌ SSH")
	}

	if svcConfig.Ntpd.Prefer != "" {
		enabledCount++
		serviceStatus = append(serviceStatus, "✅ NTP")
	} else {
		serviceStatus = append(serviceStatus, "❌ NTP")
	}

	// Count DHCP services
	dhcpEnabled := 0
	for _, dhcp := range svcConfig.Dhcpd.Items {
		if dhcp.Enable != "" {
			dhcpEnabled++
		}
	}
	enabledCount += dhcpEnabled
	totalServices += len(svcConfig.Dhcpd.Items)

	if dhcpEnabled > 0 {
		serviceStatus = append(serviceStatus, fmt.Sprintf("✅ DHCP (%d interfaces)", dhcpEnabled))
	} else {
		serviceStatus = append(serviceStatus, "❌ DHCP")
	}

	buf.WriteString(fmt.Sprintf("**Enabled Services**: %d/%d\n\n", enabledCount, totalServices))
	for _, status := range serviceStatus {
		buf.WriteString(fmt.Sprintf("- %s\n", status))
	}
	buf.WriteString("\n")

	// TODO: Add sections for OpenVPN and other VPN services when model supports them
	buf.WriteString("### OpenVPN\n\n*OpenVPN configuration not available in current model*\n\n")
	buf.WriteString("### Other VPN Services\n\n*VPN service configuration not available in current model*\n\n")

	return buf.String()
}
