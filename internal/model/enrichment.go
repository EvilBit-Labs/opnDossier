// Package model defines the data structures for OPNsense configurations.
package model

import (
	"fmt"
)

const (
	// ProtocolHTTPS is the HTTPS protocol constant.
	ProtocolHTTPS = "https"
	// ProtocolHTTP is the HTTP protocol constant.
	ProtocolHTTP = "http"
	// RuleTypePass is the pass rule type constant.
	RuleTypePass = "pass"
	// RuleTypeBlock is the block rule type constant.
	RuleTypeBlock = "block"
	// NetworkAny is the "any" network constant.
	NetworkAny = "any"

	// MaxComplexityScore is the maximum complexity score.
	MaxComplexityScore = 100
	// MaxSecurityScore is the maximum security score.
	MaxSecurityScore = 100
	// MaxComplianceScore is the maximum compliance score.
	MaxComplianceScore = 100
	// RuleComplexityWeight is the weight for rule complexity calculation.
	RuleComplexityWeight = 2
	// ServiceComplexityWeight is the weight for service complexity calculation.
	ServiceComplexityWeight = 3
	// MaxRulesThreshold is the threshold for too many rules.
	MaxRulesThreshold = 100

	// BaseSecurityScore is the base security score.
	BaseSecurityScore = 50
	// BaseResourceUsage is the base resource usage.
	BaseResourceUsage = 50
)

// EnrichedOpnSenseDocument extends OpnSenseDocument with calculated fields and analysis data.
type EnrichedOpnSenseDocument struct {
	*OpnSenseDocument

	// Calculated statistics
	Statistics *Statistics `json:"statistics,omitempty"`

	// Analysis data
	Analysis *Analysis `json:"analysis,omitempty"`

	// Security assessment
	SecurityAssessment *SecurityAssessment `json:"securityAssessment,omitempty"`

	// Performance metrics
	PerformanceMetrics *PerformanceMetrics `json:"performanceMetrics,omitempty"`

	// Compliance checks
	ComplianceChecks *ComplianceChecks `json:"complianceChecks,omitempty"`
}

// Statistics contains calculated statistics about the configuration.
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

// DHCPScopeStatistics contains statistics for a DHCP scope.
type DHCPScopeStatistics struct {
	Interface string `json:"interface"`
	Enabled   bool   `json:"enabled"`
	From      string `json:"from"`
	To        string `json:"to"`
}

// ServiceStatistics contains statistics for a service.
type ServiceStatistics struct {
	Name    string            `json:"name"`
	Enabled bool              `json:"enabled"`
	Details map[string]string `json:"details,omitempty"`
}

// StatisticsSummary contains summary statistics.
type StatisticsSummary struct {
	TotalConfigItems    int  `json:"totalConfigItems"`
	SecurityScore       int  `json:"securityScore"`
	ConfigComplexity    int  `json:"configComplexity"`
	HasSecurityFeatures bool `json:"hasSecurityFeatures"`
}

// Analysis contains analysis findings and insights.
type Analysis struct {
	// Dead rule detection
	DeadRules []DeadRuleFinding `json:"deadRules,omitempty"`

	// Unused interfaces
	UnusedInterfaces []UnusedInterfaceFinding `json:"unusedInterfaces,omitempty"`

	// Security issues
	SecurityIssues []SecurityFinding `json:"securityIssues,omitempty"`

	// Performance issues
	PerformanceIssues []PerformanceFinding `json:"performanceIssues,omitempty"`

	// Consistency issues
	ConsistencyIssues []ConsistencyFinding `json:"consistencyIssues,omitempty"`
}

// DeadRuleFinding represents a dead rule finding.
type DeadRuleFinding struct {
	RuleIndex      int    `json:"ruleIndex"`
	Interface      string `json:"interface"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// UnusedInterfaceFinding represents an unused interface finding.
type UnusedInterfaceFinding struct {
	InterfaceName  string `json:"interfaceName"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// SecurityFinding represents a security finding.
type SecurityFinding struct {
	Component      string `json:"component"`
	Issue          string `json:"issue"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// PerformanceFinding represents a performance finding.
type PerformanceFinding struct {
	Component      string `json:"component"`
	Issue          string `json:"issue"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// ConsistencyFinding represents a consistency finding.
type ConsistencyFinding struct {
	Component      string `json:"component"`
	Issue          string `json:"issue"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// SecurityAssessment contains security assessment data.
type SecurityAssessment struct {
	OverallScore     int      `json:"overallScore"`
	SecurityFeatures []string `json:"securityFeatures"`
	Vulnerabilities  []string `json:"vulnerabilities"`
	Recommendations  []string `json:"recommendations"`
}

// PerformanceMetrics contains performance metrics.
type PerformanceMetrics struct {
	ConfigComplexity int `json:"configComplexity"`
	RuleEfficiency   int `json:"ruleEfficiency"`
	ResourceUsage    int `json:"resourceUsage"`
}

// ComplianceChecks contains compliance check results.
type ComplianceChecks struct {
	ComplianceScore int      `json:"complianceScore"`
	ComplianceItems []string `json:"complianceItems"`
	Violations      []string `json:"violations"`
}

// EnrichDocument returns an EnrichedOpnSenseDocument containing computed statistics, analysis findings, security assessment, performance metrics, and compliance checks for the provided OpnSenseDocument.
// Returns nil if the input configuration is nil.
func EnrichDocument(cfg *OpnSenseDocument) *EnrichedOpnSenseDocument {
	if cfg == nil {
		return nil
	}

	enriched := &EnrichedOpnSenseDocument{
		OpnSenseDocument:   cfg,
		Statistics:         generateStatistics(cfg),
		Analysis:           generateAnalysis(cfg),
		SecurityAssessment: generateSecurityAssessment(cfg),
		PerformanceMetrics: generatePerformanceMetrics(cfg),
		ComplianceChecks:   generateComplianceChecks(cfg),
	}

	return enriched
}

// generateStatistics compiles detailed statistics from an OPNsense configuration document.
//
// The returned Statistics struct includes counts and breakdowns of interfaces, firewall rules, NAT settings, DHCP scopes, users, groups, enabled services, system settings, and detected security features. It also provides summary metrics such as total configuration items, calculated security score, configuration complexity, and the presence of security features.
//
// Returns nil if the input configuration is nil.
func generateStatistics(cfg *OpnSenseDocument) *Statistics {
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
	if cfg.Unbound.Enable != "" {
		stats.EnabledServices = append(stats.EnabledServices, "unbound")
		serviceCount++
	}
	if cfg.Snmpd.ROCommunity != "" {
		stats.EnabledServices = append(stats.EnabledServices, "snmpd")
		serviceCount++
	}
	if cfg.Ntpd.Prefer != "" {
		stats.EnabledServices = append(stats.EnabledServices, "ntpd")
		serviceCount++
	}
	stats.TotalServices = serviceCount

	// System configuration statistics
	stats.SysctlSettings = len(cfg.Sysctl)
	stats.LoadBalancerMonitors = 0 // TODO: Implement when load balancer is added

	// Security features
	if cfg.System.WebGUI.Protocol == ProtocolHTTPS {
		stats.SecurityFeatures = append(stats.SecurityFeatures, "https-web-gui")
	}
	if cfg.System.SSH.Group != "" {
		stats.SecurityFeatures = append(stats.SecurityFeatures, "ssh-access")
	}

	// Calculate summary statistics
	stats.Summary = StatisticsSummary{
		TotalConfigItems:    stats.TotalInterfaces + stats.TotalFirewallRules + stats.TotalUsers + stats.TotalGroups + stats.TotalServices,
		SecurityScore:       calculateSecurityScore(cfg, stats),
		ConfigComplexity:    calculateConfigComplexity(stats),
		HasSecurityFeatures: len(stats.SecurityFeatures) > 0,
	}

	return stats
}

// generateAnalysis performs a comprehensive analysis of the given OPNsense configuration, returning findings on dead rules, unused interfaces, security issues, performance issues, and consistency issues.
func generateAnalysis(cfg *OpnSenseDocument) *Analysis {
	analysis := &Analysis{
		DeadRules:         []DeadRuleFinding{},
		UnusedInterfaces:  []UnusedInterfaceFinding{},
		SecurityIssues:    []SecurityFinding{},
		PerformanceIssues: []PerformanceFinding{},
		ConsistencyIssues: []ConsistencyFinding{},
	}

	// Analyze dead rules
	analysis.DeadRules = analyzeDeadRules(cfg)

	// Analyze unused interfaces
	analysis.UnusedInterfaces = analyzeUnusedInterfaces(cfg)

	// Analyze security issues
	analysis.SecurityIssues = analyzeSecurityIssues(cfg)

	// Analyze performance issues
	analysis.PerformanceIssues = analyzePerformanceIssues(cfg)

	// Analyze consistency issues
	analysis.ConsistencyIssues = analyzeConsistencyIssues(cfg)

	return analysis
}

// analyzeDeadRules identifies firewall rules that are either unreachable due to preceding block-all rules or are overly permissive pass rules lacking descriptions.
// It returns a slice of findings highlighting dead or potentially problematic rules with recommendations for remediation.
func analyzeDeadRules(cfg *OpnSenseDocument) []DeadRuleFinding {
	var findings []DeadRuleFinding
	rules := cfg.FilterRules()

	for i, rule := range rules {
		// Check for "block all" rules that make subsequent rules unreachable
		if rule.Type == RuleTypeBlock && rule.Source.Network == NetworkAny {
			// If there are rules after this block-all rule, they're dead
			if i < len(rules)-1 {
				findings = append(findings, DeadRuleFinding{
					RuleIndex:      i + 1,
					Interface:      rule.Interface,
					Description:    fmt.Sprintf("Rules after position %d on interface %s are unreachable due to preceding block-all rule", i+1, rule.Interface),
					Recommendation: "Remove unreachable rules or reorder them before the block-all rule",
				})
			}
		}

		// Check for overly broad rules that might be unintentional
		if rule.Type == RuleTypePass && rule.Source.Network == NetworkAny && rule.Descr == "" {
			findings = append(findings, DeadRuleFinding{
				RuleIndex:      i + 1,
				Interface:      rule.Interface,
				Description:    fmt.Sprintf("Rule at position %d on interface %s allows all traffic without description", i+1, rule.Interface),
				Recommendation: "Add description and consider restricting source or destination",
			})
		}
	}

	return findings
}

// analyzeUnusedInterfaces identifies configured interfaces that are not referenced in any firewall rules.
// It returns a list of findings for each unused interface, including a description and recommendation.
func analyzeUnusedInterfaces(cfg *OpnSenseDocument) []UnusedInterfaceFinding {
	var findings []UnusedInterfaceFinding

	// Check if interfaces are configured but not used in rules
	interfaces := []string{"wan", "lan"}
	rules := cfg.FilterRules()
	usedInterfaces := make(map[string]bool)

	for _, rule := range rules {
		usedInterfaces[rule.Interface] = true
	}

	for _, iface := range interfaces {
		if !usedInterfaces[iface] {
			findings = append(findings, UnusedInterfaceFinding{
				InterfaceName:  iface,
				Description:    fmt.Sprintf("Interface %s is configured but not used in any firewall rules", iface),
				Recommendation: "Add firewall rules for this interface or remove unused configuration",
			})
		}
	}

	return findings
}

// analyzeSecurityIssues identifies security issues in the OPNsense configuration, such as an insecure web GUI protocol and overly permissive firewall rules.
// 
// It returns a slice of SecurityFinding detailing each detected issue with severity, description, and recommended remediation.
func analyzeSecurityIssues(cfg *OpnSenseDocument) []SecurityFinding {
	var findings []SecurityFinding

	// Check web GUI security
	if cfg.System.WebGUI.Protocol != ProtocolHTTPS {
		findings = append(findings, SecurityFinding{
			Component:      "system.webgui",
			Issue:          "insecure-web-gui",
			Severity:       "high",
			Description:    "Web GUI is not using HTTPS",
			Recommendation: "Configure HTTPS for web GUI access",
		})
	}

	// Check for overly permissive rules
	rules := cfg.FilterRules()
	for i, rule := range rules {
		if rule.Type == RuleTypePass && rule.Source.Network == NetworkAny && rule.Destination.Network == NetworkAny {
			findings = append(findings, SecurityFinding{
				Component:      fmt.Sprintf("filter.rule[%d]", i),
				Issue:          "overly-permissive-rule",
				Severity:       "medium",
				Description:    fmt.Sprintf("Rule at position %d allows all traffic from any source to any destination", i+1),
				Recommendation: "Restrict source and destination to specific networks or hosts",
			})
		}
	}

	return findings
}

// analyzePerformanceIssues returns performance findings for the given configuration, flagging if the number of firewall rules exceeds the defined threshold.
func analyzePerformanceIssues(cfg *OpnSenseDocument) []PerformanceFinding {
	var findings []PerformanceFinding

	// Check for too many rules
	rules := cfg.FilterRules()
	if len(rules) > MaxRulesThreshold {
		findings = append(findings, PerformanceFinding{
			Component:      "filter.rules",
			Issue:          "too-many-rules",
			Severity:       "medium",
			Description:    fmt.Sprintf("Configuration has %d firewall rules, which may impact performance", len(rules)),
			Recommendation: "Consider consolidating or removing unnecessary rules",
		})
	}

	return findings
}

// analyzeConsistencyIssues returns a list of consistency findings for firewall rules lacking descriptions.
// Each finding identifies a rule missing a description and recommends adding explanatory text.
func analyzeConsistencyIssues(cfg *OpnSenseDocument) []ConsistencyFinding {
	var findings []ConsistencyFinding

	// Check for missing descriptions on rules
	rules := cfg.FilterRules()
	for i, rule := range rules {
		if rule.Descr == "" {
			findings = append(findings, ConsistencyFinding{
				Component:      fmt.Sprintf("filter.rule[%d]", i),
				Issue:          "missing-description",
				Severity:       "low",
				Description:    fmt.Sprintf("Rule at position %d has no description", i+1),
				Recommendation: "Add descriptive text to explain the rule's purpose",
			})
		}
	}

	return findings
}

// generateSecurityAssessment evaluates the security posture of the given OPNsense configuration.
// It checks for HTTPS usage on the web GUI and SSH access configuration, identifies security features and vulnerabilities, provides recommendations, and assigns an overall security score.
func generateSecurityAssessment(cfg *OpnSenseDocument) *SecurityAssessment {
	assessment := &SecurityAssessment{
		SecurityFeatures: []string{},
		Vulnerabilities:  []string{},
		Recommendations:  []string{},
	}

	// Check security features
	if cfg.System.WebGUI.Protocol == ProtocolHTTPS {
		assessment.SecurityFeatures = append(assessment.SecurityFeatures, "HTTPS Web GUI")
	} else {
		assessment.Vulnerabilities = append(assessment.Vulnerabilities, "Insecure Web GUI (HTTP)")
		assessment.Recommendations = append(assessment.Recommendations, "Configure HTTPS for web GUI")
	}

	if cfg.System.SSH.Group != "" {
		assessment.SecurityFeatures = append(assessment.SecurityFeatures, "SSH Access Configured")
	} else {
		assessment.Vulnerabilities = append(assessment.Vulnerabilities, "No SSH access configured")
		assessment.Recommendations = append(assessment.Recommendations, "Configure SSH access for remote management")
	}

	// Calculate overall score (0-100)
	score := BaseSecurityScore // Base score
	if cfg.System.WebGUI.Protocol == ProtocolHTTPS {
		score += 25
	}
	if cfg.System.SSH.Group != "" {
		score += 25
	}

	assessment.OverallScore = score

	return assessment
}

// generatePerformanceMetrics calculates performance metrics for an OPNsense configuration, including configuration complexity, rule efficiency, and resource usage.
func generatePerformanceMetrics(cfg *OpnSenseDocument) *PerformanceMetrics {
	metrics := &PerformanceMetrics{}

	// Calculate config complexity based on number of rules, interfaces, etc.
	rules := cfg.FilterRules()
	complexity := len(rules) * RuleComplexityWeight
	complexity += len(cfg.System.User) * 1
	complexity += len(cfg.System.Group) * 1

	metrics.ConfigComplexity = min(complexity, MaxComplexityScore)

	// Calculate rule efficiency (simplified)
	if len(rules) > 0 {
		metrics.RuleEfficiency = max(MaxComplexityScore-(len(rules)*RuleComplexityWeight), 0)
	} else {
		metrics.RuleEfficiency = MaxComplexityScore
	}

	// Calculate resource usage (simplified)
	metrics.ResourceUsage = BaseResourceUsage // Base usage

	return metrics
}

// generateComplianceChecks evaluates the configuration for compliance with key security requirements.
// It checks for HTTPS usage on the web GUI and SSH access configuration, records passed items and violations, and computes a compliance score based on the results.
func generateComplianceChecks(cfg *OpnSenseDocument) *ComplianceChecks {
	checks := &ComplianceChecks{
		ComplianceItems: []string{},
		Violations:      []string{},
	}

	// Check compliance items
	if cfg.System.WebGUI.Protocol == ProtocolHTTPS {
		checks.ComplianceItems = append(checks.ComplianceItems, "HTTPS Web GUI")
	} else {
		checks.Violations = append(checks.Violations, "Web GUI not using HTTPS")
	}

	if cfg.System.SSH.Group != "" {
		checks.ComplianceItems = append(checks.ComplianceItems, "SSH Access Configured")
	} else {
		checks.Violations = append(checks.Violations, "No SSH access configured")
	}

	// Calculate compliance score
	totalChecks := 2 // Number of compliance checks
	passedChecks := len(checks.ComplianceItems)
	checks.ComplianceScore = (passedChecks * MaxComplianceScore) / totalChecks

	return checks
}

// calculateSecurityScore computes a security score for the given OPNsense configuration.
// The score is based on the presence of security features such as HTTPS web GUI and SSH access,
// and is reduced for overly permissive firewall rules. The result is clamped between 0 and the maximum security score.
func calculateSecurityScore(cfg *OpnSenseDocument, stats *Statistics) int {
	score := 50 // Base score

	// Add points for security features
	if cfg.System.WebGUI.Protocol == ProtocolHTTPS {
		score += 20
	}
	if cfg.System.SSH.Group != "" {
		score += 15
	}
	if len(stats.SecurityFeatures) > 0 {
		score += 15
	}

	// Subtract points for security issues
	if len(stats.RulesByType) > 0 {
		// Check for overly permissive rules
		rules := cfg.FilterRules()
		for _, rule := range rules {
			if rule.Type == RuleTypePass && rule.Source.Network == NetworkAny && rule.Destination.Network == NetworkAny {
				score -= 10
			}
		}
	}

	if score < 0 {
		score = 0
	}
	if score > MaxSecurityScore {
		score = MaxSecurityScore
	}

	return score
}

// calculateConfigComplexity returns a configuration complexity score based on the weighted sum of firewall rules, users, groups, and services, capped at the maximum allowed complexity score.
func calculateConfigComplexity(stats *Statistics) int {
	complexity := stats.TotalFirewallRules * RuleComplexityWeight
	complexity += stats.TotalUsers * 1
	complexity += stats.TotalGroups * 1
	complexity += stats.TotalServices * ServiceComplexityWeight

	if complexity > MaxComplexityScore {
		return MaxComplexityScore
	}
	return complexity
}
