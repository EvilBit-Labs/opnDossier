package processor

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nao1215/markdown"
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
	NormalizedConfig *model.Opnsense `json:"normalizedConfig,omitempty"`

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
func NewReport(cfg *model.Opnsense, processorConfig Config) *Report {
	report := &Report{
		GeneratedAt:     time.Now().UTC(),
		ProcessorConfig: processorConfig,
		Findings:        Findings{},
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
	md.PlainText("Generated: " + r.GeneratedAt.Format(time.RFC3339))
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
func generateStatistics(cfg *model.Opnsense) *Statistics {
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
	stats.InterfaceDetails = append(stats.InterfaceDetails,
		InterfaceStatistics{
			Name:        "wan",
			Type:        "wan",
			Enabled:     cfg.Interfaces.Wan.Enable != "",
			HasIPv4:     cfg.Interfaces.Wan.IPAddr != "",
			HasIPv6:     cfg.Interfaces.Wan.IPAddrv6 != "",
			HasDHCP:     cfg.Dhcpd.Wan.Enable != "",
			BlockPriv:   cfg.Interfaces.Wan.BlockPriv != "",
			BlockBogons: cfg.Interfaces.Wan.BlockBogons != "",
		},
		InterfaceStatistics{
			Name:        "lan",
			Type:        "lan",
			Enabled:     cfg.Interfaces.Lan.Enable != "",
			HasIPv4:     cfg.Interfaces.Lan.IPAddr != "",
			HasIPv6:     cfg.Interfaces.Lan.IPAddrv6 != "",
			HasDHCP:     cfg.Dhcpd.Lan.Enable != "",
			BlockPriv:   cfg.Interfaces.Lan.BlockPriv != "",
			BlockBogons: cfg.Interfaces.Lan.BlockBogons != "",
		},
	)

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
	if cfg.Dhcpd.Lan.Enable != "" {
		dhcpScopes++
		stats.DHCPScopeDetails = append(stats.DHCPScopeDetails, DHCPScopeStatistics{
			Interface: "lan",
			Enabled:   true,
			From:      cfg.Dhcpd.Lan.Range.From,
			To:        cfg.Dhcpd.Lan.Range.To,
		})
	}
	if cfg.Dhcpd.Wan.Enable != "" {
		dhcpScopes++
		stats.DHCPScopeDetails = append(stats.DHCPScopeDetails, DHCPScopeStatistics{
			Interface: "wan",
			Enabled:   true,
			From:      cfg.Dhcpd.Wan.Range.From,
			To:        cfg.Dhcpd.Wan.Range.To,
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
	if cfg.Dhcpd.Lan.Enable != "" {
		stats.EnabledServices = append(stats.EnabledServices, "DHCP Server (LAN)")
		stats.ServiceDetails = append(stats.ServiceDetails, ServiceStatistics{
			Name:    "DHCP Server (LAN)",
			Enabled: true,
			Details: map[string]string{
				"interface": "lan",
				"from":      cfg.Dhcpd.Lan.Range.From,
				"to":        cfg.Dhcpd.Lan.Range.To,
			},
		})
		serviceCount++
	}
	if cfg.Dhcpd.Wan.Enable != "" {
		stats.EnabledServices = append(stats.EnabledServices, "DHCP Server (WAN)")
		stats.ServiceDetails = append(stats.ServiceDetails, ServiceStatistics{
			Name:    "DHCP Server (WAN)",
			Enabled: true,
			Details: map[string]string{
				"interface": "wan",
				"from":      cfg.Dhcpd.Wan.Range.From,
				"to":        cfg.Dhcpd.Wan.Range.To,
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
	if cfg.Interfaces.Wan.BlockPriv != "" {
		stats.SecurityFeatures = append(stats.SecurityFeatures, "Block Private Networks")
	}
	if cfg.Interfaces.Wan.BlockBogons != "" {
		stats.SecurityFeatures = append(stats.SecurityFeatures, "Block Bogon Networks")
	}
	if cfg.System.Webgui.Protocol == "https" {
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
func calculateSecurityScore(cfg *model.Opnsense, stats *Statistics) int {
	score := 0

	// Security features contribute to score
	score += len(stats.SecurityFeatures) * SecurityFeatureMultiplier

	// Firewall rules indicate active security configuration
	if stats.TotalFirewallRules > 0 {
		score += 20
	}

	// HTTPS web interface
	if cfg.System.Webgui.Protocol == "https" {
		score += 15
	}

	// SSH configuration
	if cfg.System.SSH.Group != "" {
		score += 10
	}

	// Cap at MaxSecurityScore
	if score > MaxSecurityScore {
		score = 100
	}

	return score
}

// calculateConfigComplexity computes a complexity score based on configuration items.
func calculateConfigComplexity(stats *Statistics) int {
	complexity := 0

	// Each configuration type adds to complexity
	complexity += stats.TotalInterfaces * InterfaceComplexityWeight
	complexity += stats.TotalFirewallRules * FirewallRuleComplexityWeight
	complexity += stats.TotalUsers * UserComplexityWeight
	complexity += stats.TotalGroups * GroupComplexityWeight
	complexity += stats.SysctlSettings * SysctlComplexityWeight
	complexity += stats.TotalServices * ServiceComplexityWeight
	complexity += stats.DHCPScopes * DHCPComplexityWeight
	complexity += stats.LoadBalancerMonitors * LoadBalancerComplexityWeight

	// Normalize to 0-100 scale (assuming max reasonable config)
	normalizedComplexity := (complexity * MaxComplexityScore) / MaxReasonableComplexity
	if normalizedComplexity > MaxComplexityScore {
		normalizedComplexity = MaxComplexityScore
	}

	return normalizedComplexity
}
