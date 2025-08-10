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

	// NAT Summary for prominent display
	NATSummary *NATSummary `json:"natSummary,omitempty"`
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
		NATSummary:         generateNATSummary(cfg),
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

	// Generate interface statistics
	generateInterfaceStatistics(cfg, stats)

	// Generate firewall rule statistics
	generateFirewallStatistics(cfg, stats)

	// Generate DHCP statistics
	generateDHCPStatistics(cfg, stats)

	// Generate user and group statistics
	generateUserGroupStatistics(cfg, stats)

	// Generate service statistics
	generateServiceStatistics(cfg, stats)

	// Generate security features
	generateSecurityFeatures(cfg, stats)

	// Calculate summary statistics
	stats.Summary = StatisticsSummary{
		TotalConfigItems:    stats.TotalInterfaces + stats.TotalFirewallRules + stats.TotalUsers + stats.TotalGroups + stats.TotalServices,
		SecurityScore:       calculateSecurityScore(cfg, stats),
		ConfigComplexity:    calculateConfigComplexity(stats),
		HasSecurityFeatures: len(stats.SecurityFeatures) > 0,
	}

	return stats
}

// generateInterfaceStatistics extracts interface-related statistics from the configuration.
func generateInterfaceStatistics(cfg *OpnSenseDocument, stats *Statistics) {
	interfaceNames := cfg.Interfaces.Names()
	stats.TotalInterfaces = len(interfaceNames)

	// Count interfaces by type and build interface details
	for _, ifaceName := range interfaceNames {
		// Count by interface type (wan, lan, opt0, opt1, etc.)
		stats.InterfacesByType[ifaceName]++

		// Get interface configuration
		iface, exists := cfg.Interfaces.Get(ifaceName)
		if !exists {
			continue
		}

		// Create interface statistics
		ifaceStats := InterfaceStatistics{
			Name: ifaceName,
			Type: ifaceName,
		}

		// Check if interface is enabled
		ifaceStats.Enabled = iface.Enable != ""
		ifaceStats.HasIPv4 = iface.IPAddr != ""
		ifaceStats.HasIPv6 = iface.IPAddrv6 != ""
		ifaceStats.BlockPriv = iface.BlockPriv != ""
		ifaceStats.BlockBogons = iface.BlockBogons != ""

		// Check for DHCP configuration
		if dhcpIface, dhcpExists := cfg.Dhcpd.Get(ifaceName); dhcpExists {
			ifaceStats.HasDHCP = dhcpIface.Enable != ""
		}

		stats.InterfaceDetails = append(stats.InterfaceDetails, ifaceStats)
	}
}

// generateFirewallStatistics extracts firewall rule and NAT statistics from the configuration.
func generateFirewallStatistics(cfg *OpnSenseDocument, stats *Statistics) {
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
}

// generateDHCPStatistics extracts DHCP-related statistics from the configuration.
func generateDHCPStatistics(cfg *OpnSenseDocument, stats *Statistics) {
	dhcpScopes := 0
	dhcpInterfaceNames := cfg.Dhcpd.Names()

	for _, dhcpIfaceName := range dhcpInterfaceNames {
		if dhcpIface, exists := cfg.Dhcpd.Get(dhcpIfaceName); exists && dhcpIface.Enable != "" {
			dhcpScopes++

			stats.DHCPScopeDetails = append(stats.DHCPScopeDetails, DHCPScopeStatistics{
				Interface: dhcpIfaceName,
				Enabled:   true,
				From:      dhcpIface.Range.From,
				To:        dhcpIface.Range.To,
			})
		}
	}

	stats.DHCPScopes = dhcpScopes
}

// generateUserGroupStatistics extracts user and group statistics from the configuration.
func generateUserGroupStatistics(cfg *OpnSenseDocument, stats *Statistics) {
	stats.TotalUsers = len(cfg.System.User)

	stats.TotalGroups = len(cfg.System.Group)
	for _, user := range cfg.System.User {
		stats.UsersByScope[user.Scope]++
	}

	for _, group := range cfg.System.Group {
		stats.GroupsByScope[group.Scope]++
	}
}

// generateServiceStatistics extracts service-related statistics from the configuration.
func generateServiceStatistics(cfg *OpnSenseDocument, stats *Statistics) {
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
}

// generateSecurityFeatures extracts security-related features from the configuration.
func generateSecurityFeatures(cfg *OpnSenseDocument, stats *Statistics) {
	if cfg.System.WebGUI.Protocol == ProtocolHTTPS {
		stats.SecurityFeatures = append(stats.SecurityFeatures, "https-web-gui")
	}

	if cfg.System.SSH.Group != "" {
		stats.SecurityFeatures = append(stats.SecurityFeatures, "ssh-access")
	}
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
					RuleIndex: i + 1,
					Interface: rule.Interface.String(),
					Description: fmt.Sprintf(
						"Rules after position %d on interface %s are unreachable due to preceding block-all rule",
						i+1,
						rule.Interface.String(),
					),
					Recommendation: "Remove unreachable rules or reorder them before the block-all rule",
				})
			}
		}

		// Check for overly broad rules that might be unintentional
		if rule.Type == RuleTypePass && rule.Source.Network == NetworkAny && rule.Descr == "" {
			findings = append(findings, DeadRuleFinding{
				RuleIndex: i + 1,
				Interface: rule.Interface.String(),
				Description: fmt.Sprintf(
					"Rule at position %d on interface %s allows all traffic without description",
					i+1,
					rule.Interface.String(),
				),
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

	// Dynamically build interface list based on configured interfaces
	interfaceNames := cfg.Interfaces.Names()
	interfaces := make([]string, 0, len(interfaceNames))

	// Add each configured interface to the list
	interfaces = append(interfaces, interfaceNames...)

	rules := cfg.FilterRules()
	usedInterfaces := make(map[string]bool)

	for _, rule := range rules {
		// Mark all interfaces in the rule as used
		for _, iface := range rule.Interface {
			usedInterfaces[iface] = true
		}
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
				Component: fmt.Sprintf("filter.rule[%d]", i),
				Issue:     "overly-permissive-rule",
				Severity:  "medium",
				Description: fmt.Sprintf(
					"Rule at position %d allows all traffic from any source to any destination",
					i+1,
				),
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
			Component: "filter.rules",
			Issue:     "too-many-rules",
			Severity:  "medium",
			Description: fmt.Sprintf(
				"Configuration has %d firewall rules, which may impact performance",
				len(rules),
			),
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

	// Calculate overall score using shared helper
	assessment.OverallScore = calculateSecurityScoreBase(cfg, nil)

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
	score := calculateSecurityScoreBase(cfg, stats)

	// Subtract points for security issues
	if len(stats.RulesByType) > 0 {
		// Check for overly permissive rules
		rules := cfg.FilterRules()
		for _, rule := range rules {
			if rule.Type == RuleTypePass && rule.Source.Network == NetworkAny &&
				rule.Destination.Network == NetworkAny {
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

// calculateSecurityScoreBase computes the base security score for the given OPNsense configuration.
// This shared helper function centralizes the common security scoring logic used by both
// generateSecurityAssessment and calculateSecurityScore functions.
func calculateSecurityScoreBase(cfg *OpnSenseDocument, stats *Statistics) int {
	score := BaseSecurityScore // Base score

	// Add points for security features
	if cfg.System.WebGUI.Protocol == ProtocolHTTPS {
		score += 25
	}

	if cfg.System.SSH.Group != "" {
		score += 25
	}

	if stats != nil && len(stats.SecurityFeatures) > 0 {
		score += 15
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

// generateNATSummary creates a comprehensive NAT summary for security analysis.
// This includes NAT mode, reflection settings, outbound rules, and port forwarding information.
func generateNATSummary(cfg *OpnSenseDocument) *NATSummary {
	if cfg == nil {
		return nil
	}

	summary := &NATSummary{
		Mode:               cfg.Nat.Outbound.Mode,
		ReflectionDisabled: cfg.System.DisableNATReflection == "yes",
		PfShareForward:     cfg.System.PfShareForward == 1,
		OutboundRules:      cfg.Nat.Outbound.Rule,
		InboundRules:       cfg.Nat.Inbound,
	}

	return summary
}
