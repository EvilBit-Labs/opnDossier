package model

// Statistics contains calculated statistics about a device configuration.
type Statistics struct {
	// TotalInterfaces is the total number of configured interfaces.
	TotalInterfaces int `json:"totalInterfaces,omitempty" yaml:"totalInterfaces,omitempty"`
	// InterfacesByType maps interface type names to their counts.
	InterfacesByType map[string]int `json:"interfacesByType,omitempty" yaml:"interfacesByType,omitempty"`
	// InterfaceDetails contains per-interface statistics.
	InterfaceDetails []InterfaceStatistics `json:"interfaceDetails,omitempty" yaml:"interfaceDetails,omitempty"`

	// TotalVLANs is the total number of configured VLANs.
	TotalVLANs int `json:"totalVlans,omitempty" yaml:"totalVlans,omitempty"`
	// TotalBridges is the total number of configured bridges.
	TotalBridges int `json:"totalBridges,omitempty" yaml:"totalBridges,omitempty"`
	// TotalCertificates is the total number of certificates.
	TotalCertificates int `json:"totalCertificates,omitempty" yaml:"totalCertificates,omitempty"`
	// TotalCAs is the total number of certificate authorities.
	TotalCAs int `json:"totalCas,omitempty" yaml:"totalCas,omitempty"`

	// TotalFirewallRules is the total number of firewall filter rules.
	TotalFirewallRules int `json:"totalFirewallRules,omitempty" yaml:"totalFirewallRules,omitempty"`
	// RulesByInterface maps interface names to their firewall rule counts.
	RulesByInterface map[string]int `json:"rulesByInterface,omitempty" yaml:"rulesByInterface,omitempty"`
	// RulesByType maps rule types (pass, block, reject) to their counts.
	RulesByType map[string]int `json:"rulesByType,omitempty" yaml:"rulesByType,omitempty"`
	// NATEntries is the total number of NAT rules (inbound and outbound).
	NATEntries int `json:"natEntries,omitempty" yaml:"natEntries,omitempty"`
	// NATMode is the outbound NAT mode.
	NATMode NATOutboundMode `json:"natMode,omitempty" yaml:"natMode,omitempty"`

	// TotalGateways is the total number of configured gateways.
	TotalGateways int `json:"totalGateways,omitempty" yaml:"totalGateways,omitempty"`
	// TotalGatewayGroups is the total number of gateway groups.
	TotalGatewayGroups int `json:"totalGatewayGroups,omitempty" yaml:"totalGatewayGroups,omitempty"`

	// DHCPScopes is the number of enabled DHCP scopes.
	DHCPScopes int `json:"dhcpScopes,omitempty" yaml:"dhcpScopes,omitempty"`
	// DHCPScopeDetails contains per-scope DHCP statistics.
	DHCPScopeDetails []DHCPScopeStatistics `json:"dhcpScopeDetails,omitempty" yaml:"dhcpScopeDetails,omitempty"`

	// TotalUsers is the total number of system user accounts.
	TotalUsers int `json:"totalUsers,omitempty" yaml:"totalUsers,omitempty"`
	// UsersByScope maps user scopes to their counts.
	UsersByScope map[string]int `json:"usersByScope,omitempty" yaml:"usersByScope,omitempty"`
	// TotalGroups is the total number of system groups.
	TotalGroups int `json:"totalGroups,omitempty" yaml:"totalGroups,omitempty"`
	// GroupsByScope maps group scopes to their counts.
	GroupsByScope map[string]int `json:"groupsByScope,omitempty" yaml:"groupsByScope,omitempty"`

	// EnabledServices lists the names of active services.
	EnabledServices []string `json:"enabledServices,omitempty" yaml:"enabledServices,omitempty"`
	// TotalServices is the total number of configured services.
	TotalServices int `json:"totalServices,omitempty" yaml:"totalServices,omitempty"`
	// ServiceDetails contains per-service statistics.
	ServiceDetails []ServiceStatistics `json:"serviceDetails,omitempty" yaml:"serviceDetails,omitempty"`

	// SysctlSettings is the total number of sysctl tunables.
	SysctlSettings int `json:"sysctlSettings,omitempty" yaml:"sysctlSettings,omitempty"`
	// LoadBalancerMonitors is the total number of load balancer health monitors.
	LoadBalancerMonitors int `json:"loadBalancerMonitors,omitempty" yaml:"loadBalancerMonitors,omitempty"`
	// SecurityFeatures lists the names of enabled security features.
	SecurityFeatures []string `json:"securityFeatures,omitempty" yaml:"securityFeatures,omitempty"`

	// Summary contains aggregated summary statistics.
	Summary StatisticsSummary `json:"summary" yaml:"summary,omitempty"`
}

// InterfaceStatistics contains detailed statistics for a single interface.
type InterfaceStatistics struct {
	// Name is the logical interface name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Type is the interface type classification.
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// Enabled indicates the interface is administratively up.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// HasIPv4 indicates an IPv4 address is configured.
	HasIPv4 bool `json:"hasIpv4,omitempty" yaml:"hasIpv4,omitempty"`
	// HasIPv6 indicates an IPv6 address is configured.
	HasIPv6 bool `json:"hasIpv6,omitempty" yaml:"hasIpv6,omitempty"`
	// HasDHCP indicates a DHCP scope exists for this interface.
	HasDHCP bool `json:"hasDhcp,omitempty" yaml:"hasDhcp,omitempty"`
	// BlockPriv indicates RFC 1918 private traffic is blocked.
	BlockPriv bool `json:"blockPriv,omitempty" yaml:"blockPriv,omitempty"`
	// BlockBogons indicates bogon traffic is blocked.
	BlockBogons bool `json:"blockBogons,omitempty" yaml:"blockBogons,omitempty"`
}

// DHCPScopeStatistics contains statistics for a DHCP scope.
type DHCPScopeStatistics struct {
	// Interface is the interface this DHCP scope is bound to.
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Enabled indicates the DHCP scope is active.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// From is the start of the DHCP address range.
	From string `json:"from,omitempty" yaml:"from,omitempty"`
	// To is the end of the DHCP address range.
	To string `json:"to,omitempty" yaml:"to,omitempty"`
}

// ServiceStatistics contains statistics for a service.
type ServiceStatistics struct {
	// Name is the service name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Enabled indicates the service is active.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// Details contains additional key-value metadata about the service.
	Details map[string]string `json:"details,omitempty" yaml:"details,omitempty"`
}

// StatisticsSummary contains summary statistics.
type StatisticsSummary struct {
	// TotalConfigItems is the total number of configuration items across all sections.
	TotalConfigItems int `json:"totalConfigItems,omitempty" yaml:"totalConfigItems,omitempty"`
	// SecurityScore is the overall security posture score (0-100).
	SecurityScore int `json:"securityScore,omitempty" yaml:"securityScore,omitempty"`
	// ConfigComplexity is a complexity metric for the configuration.
	ConfigComplexity int `json:"configComplexity,omitempty" yaml:"configComplexity,omitempty"`
	// HasSecurityFeatures indicates at least one security feature is enabled.
	HasSecurityFeatures bool `json:"hasSecurityFeatures,omitempty" yaml:"hasSecurityFeatures,omitempty"`
}

// Analysis contains analysis findings and insights.
type Analysis struct {
	// DeadRules contains firewall rules that are unreachable or redundant.
	DeadRules []DeadRuleFinding `json:"deadRules,omitempty" yaml:"deadRules,omitempty"`
	// UnusedInterfaces contains interfaces with no associated rules or services.
	UnusedInterfaces []UnusedInterfaceFinding `json:"unusedInterfaces,omitempty" yaml:"unusedInterfaces,omitempty"`
	// SecurityIssues contains detected security configuration issues.
	SecurityIssues []SecurityFinding `json:"securityIssues,omitempty" yaml:"securityIssues,omitempty"`
	// PerformanceIssues contains detected performance configuration issues.
	PerformanceIssues []PerformanceFinding `json:"performanceIssues,omitempty" yaml:"performanceIssues,omitempty"`
	// ConsistencyIssues contains detected configuration consistency issues.
	ConsistencyIssues []ConsistencyFinding `json:"consistencyIssues,omitempty" yaml:"consistencyIssues,omitempty"`
}

// Dead rule kind constants classify the reason a rule is considered dead.
const (
	// DeadRuleKindUnreachable indicates the rule is unreachable due to a preceding block-all.
	DeadRuleKindUnreachable = "unreachable"
	// DeadRuleKindDuplicate indicates the rule is a duplicate of another rule.
	DeadRuleKindDuplicate = "duplicate"
)

// DeadRuleFinding represents a dead rule finding.
type DeadRuleFinding struct {
	// Kind classifies the dead rule reason (e.g., "unreachable", "duplicate").
	Kind string `json:"kind,omitempty" yaml:"kind,omitempty"`
	// RuleIndex is the position of the dead rule in the filter rule list.
	RuleIndex int `json:"ruleIndex,omitempty" yaml:"ruleIndex,omitempty"`
	// Interface is the interface the dead rule is bound to.
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Description is a summary of why the rule is considered dead.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Recommendation is the suggested corrective action.
	Recommendation string `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
}

// UnusedInterfaceFinding represents an unused interface finding.
type UnusedInterfaceFinding struct {
	// InterfaceName is the name of the unused interface.
	InterfaceName string `json:"interfaceName,omitempty" yaml:"interfaceName,omitempty"`
	// Description is a summary of why the interface is considered unused.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Recommendation is the suggested corrective action.
	Recommendation string `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
}

// SecurityFinding represents a security finding.
type SecurityFinding struct {
	// Component is the configuration component affected by the finding.
	Component string `json:"component,omitempty" yaml:"component,omitempty"`
	// Issue is a brief summary of the finding.
	Issue string `json:"issue,omitempty" yaml:"issue,omitempty"`
	// Severity is the severity level (e.g., "critical", "high", "medium", "low").
	Severity Severity `json:"severity,omitempty" yaml:"severity,omitempty"`
	// Description is a detailed explanation of the finding.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Recommendation is the suggested corrective action.
	Recommendation string `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
}

// PerformanceFinding represents a performance finding.
type PerformanceFinding struct {
	// Component is the configuration component affected by the finding.
	Component string `json:"component,omitempty" yaml:"component,omitempty"`
	// Issue is a brief summary of the finding.
	Issue string `json:"issue,omitempty" yaml:"issue,omitempty"`
	// Severity is the severity level (e.g., "critical", "high", "medium", "low").
	Severity Severity `json:"severity,omitempty" yaml:"severity,omitempty"`
	// Description is a detailed explanation of the finding.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Recommendation is the suggested corrective action.
	Recommendation string `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
}

// ConsistencyFinding represents a consistency finding.
type ConsistencyFinding struct {
	// Component is the configuration component affected by the finding.
	Component string `json:"component,omitempty" yaml:"component,omitempty"`
	// Issue is a brief summary of the finding.
	Issue string `json:"issue,omitempty" yaml:"issue,omitempty"`
	// Severity is the severity level (e.g., "critical", "high", "medium", "low").
	Severity Severity `json:"severity,omitempty" yaml:"severity,omitempty"`
	// Description is a detailed explanation of the finding.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Recommendation is the suggested corrective action.
	Recommendation string `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
}

// SecurityAssessment contains security assessment data.
type SecurityAssessment struct {
	// OverallScore is the overall security posture score (0-100).
	OverallScore int `json:"overallScore,omitempty" yaml:"overallScore,omitempty"`
	// SecurityFeatures lists the names of enabled security features.
	SecurityFeatures []string `json:"securityFeatures,omitempty" yaml:"securityFeatures,omitempty"`
	// Vulnerabilities lists identified vulnerability descriptions.
	Vulnerabilities []string `json:"vulnerabilities,omitempty" yaml:"vulnerabilities,omitempty"`
	// Recommendations lists suggested security improvements.
	Recommendations []string `json:"recommendations,omitempty" yaml:"recommendations,omitempty"`
}

// PerformanceMetrics contains performance metrics.
type PerformanceMetrics struct {
	// ConfigComplexity is a complexity metric for the configuration.
	ConfigComplexity int `json:"configComplexity,omitempty" yaml:"configComplexity,omitempty"`
}

// ComplianceResults contains the full results of a compliance audit run,
// including per-plugin findings, controls, and summary statistics.
type ComplianceResults struct {
	// Mode is the audit report mode (e.g., "blue", "red").
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty"`
	// Findings contains top-level security analysis findings (distinct from per-plugin findings in PluginResults).
	Findings []ComplianceFinding `json:"findings,omitempty" yaml:"findings,omitempty"`
	// PluginResults contains per-plugin compliance results keyed by plugin name.
	PluginResults map[string]PluginComplianceResult `json:"pluginResults,omitempty" yaml:"pluginResults,omitempty"`
	// Summary contains the top-level aggregate summary across all plugins.
	Summary *ComplianceResultSummary `json:"summary,omitempty" yaml:"summary,omitempty"`
	// Metadata contains arbitrary audit metadata.
	Metadata map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// HasData reports whether the compliance results contain meaningful data.
func (r ComplianceResults) HasData() bool {
	return r.Mode != "" ||
		len(r.Findings) > 0 ||
		len(r.PluginResults) > 0 ||
		r.Summary != nil ||
		len(r.Metadata) > 0
}

// ComplianceFinding represents an individual compliance finding from an audit plugin.
type ComplianceFinding struct {
	// Type is the finding category (e.g., "compliance").
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// Severity is the severity level (e.g., "critical", "high", "medium", "low").
	Severity string `json:"severity,omitempty" yaml:"severity,omitempty"`
	// Title is a brief description of the finding.
	Title string `json:"title,omitempty" yaml:"title,omitempty"`
	// Description is a detailed explanation of the finding.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Recommendation is the suggested corrective action.
	Recommendation string `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
	// Component is the affected configuration component.
	Component string `json:"component,omitempty" yaml:"component,omitempty"`
	// References lists related control IDs (e.g., "STIG-V-123456").
	References []string `json:"references,omitempty" yaml:"references,omitempty"`
	// Reference provides additional information or documentation links.
	Reference string `json:"reference,omitempty" yaml:"reference,omitempty"`
	// Tags contains classification labels for the finding.
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	// Metadata contains arbitrary key-value pairs for additional context.
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	// AttackSurface contains attack surface information for red team findings.
	AttackSurface *ComplianceAttackSurface `json:"attackSurface,omitempty" yaml:"attackSurface,omitempty"`
	// ExploitNotes contains exploitation notes for red team findings.
	ExploitNotes string `json:"exploitNotes,omitempty" yaml:"exploitNotes,omitempty"`
	// Control identifies the compliance control this finding relates to.
	Control string `json:"control,omitempty" yaml:"control,omitempty"`
}

// ComplianceAttackSurface represents attack surface information for red team findings.
type ComplianceAttackSurface struct {
	// Type is the attack surface type classification.
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// Ports lists the network ports involved in the attack surface.
	Ports []int `json:"ports,omitempty" yaml:"ports,omitempty"`
	// Services lists the services involved in the attack surface.
	Services []string `json:"services,omitempty" yaml:"services,omitempty"`
	// Vulnerabilities lists the vulnerabilities associated with the attack surface.
	Vulnerabilities []string `json:"vulnerabilities,omitempty" yaml:"vulnerabilities,omitempty"`
}

// PluginComplianceResult contains the compliance results for a single audit plugin.
type PluginComplianceResult struct {
	// PluginInfo contains metadata about the plugin that produced these results.
	PluginInfo CompliancePluginInfo `json:"pluginInfo" yaml:"pluginInfo,omitempty"`
	// Findings contains compliance findings specific to this plugin.
	Findings []ComplianceFinding `json:"findings,omitempty" yaml:"findings,omitempty"`
	// Summary contains summary statistics for this plugin's results.
	Summary *ComplianceResultSummary `json:"summary,omitempty" yaml:"summary,omitempty"`
	// Controls contains the control definitions evaluated by this plugin.
	Controls []ComplianceControl `json:"controls,omitempty" yaml:"controls,omitempty"`
	// Compliance maps control IDs to their compliant/non-compliant status.
	Compliance map[string]bool `json:"compliance,omitempty" yaml:"compliance,omitempty"`
}

// CompliancePluginInfo contains metadata about an audit plugin.
type CompliancePluginInfo struct {
	// Name is the plugin name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Version is the plugin version string.
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	// Description is a brief description of the plugin's purpose.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// Control compliance status values used in audit report output (markdown tables, JSON/YAML exports).
const (
	// ControlStatusPass indicates a control is compliant.
	ControlStatusPass = "PASS"
	// ControlStatusFail indicates a control is non-compliant.
	ControlStatusFail = "FAIL"
	// ControlStatusUnknown indicates a control could not be evaluated
	// from the available configuration data.
	ControlStatusUnknown = "UNKNOWN"
)

// ComplianceControl represents a single compliance control definition from a plugin.
type ComplianceControl struct {
	// ID is the unique control identifier (e.g., "STIG-V-123456", "SANS-001").
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
	// Status is the compliance evaluation result ("PASS", "FAIL", or "UNKNOWN").
	// Derived from the Compliance map during export mapping.
	Status string `json:"status" yaml:"status"`
	// Title is the control title.
	Title string `json:"title,omitempty" yaml:"title,omitempty"`
	// Description is a detailed explanation of the control.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Category is the control's category classification.
	Category string `json:"category,omitempty" yaml:"category,omitempty"`
	// Severity is the severity level for violations of this control.
	Severity string `json:"severity,omitempty" yaml:"severity,omitempty"`
	// Rationale explains why this control is important.
	Rationale string `json:"rationale,omitempty" yaml:"rationale,omitempty"`
	// Remediation describes how to achieve compliance with this control.
	Remediation string `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	// References lists related documentation links (e.g., NIST, CIS URLs).
	References []string `json:"references,omitempty" yaml:"references,omitempty"`
	// Tags lists classification tags for the control.
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	// Metadata contains arbitrary key-value metadata about the control.
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// ComplianceResultSummary contains aggregate counts for compliance audit results.
type ComplianceResultSummary struct {
	// TotalFindings is the total number of findings.
	TotalFindings int `json:"totalFindings" yaml:"totalFindings,omitempty"`
	// CriticalFindings is the number of critical-severity findings.
	CriticalFindings int `json:"criticalFindings" yaml:"criticalFindings,omitempty"`
	// HighFindings is the number of high-severity findings.
	HighFindings int `json:"highFindings" yaml:"highFindings,omitempty"`
	// MediumFindings is the number of medium-severity findings.
	MediumFindings int `json:"mediumFindings" yaml:"mediumFindings,omitempty"`
	// LowFindings is the number of low-severity findings.
	LowFindings int `json:"lowFindings" yaml:"lowFindings,omitempty"`
	// InfoFindings is the number of informational findings.
	InfoFindings int `json:"infoFindings" yaml:"infoFindings,omitempty"`
	// PluginCount is the number of plugins that contributed results.
	PluginCount int `json:"pluginCount" yaml:"pluginCount,omitempty"`
	// Compliant is the number of controls that passed.
	Compliant int `json:"compliant" yaml:"compliant,omitempty"`
	// NonCompliant is the number of controls that failed.
	NonCompliant int `json:"nonCompliant" yaml:"nonCompliant,omitempty"`
}
