package common

// Statistics contains calculated statistics about a device configuration.
type Statistics struct {
	// TotalInterfaces is the total number of configured interfaces.
	TotalInterfaces int `json:"totalInterfaces,omitempty" yaml:"totalInterfaces,omitempty"`
	// InterfacesByType maps interface type names to their counts.
	InterfacesByType map[string]int `json:"interfacesByType,omitempty" yaml:"interfacesByType,omitempty"`
	// InterfaceDetails contains per-interface statistics.
	InterfaceDetails []InterfaceStatistics `json:"interfaceDetails,omitempty" yaml:"interfaceDetails,omitempty"`

	// TotalFirewallRules is the total number of firewall filter rules.
	TotalFirewallRules int `json:"totalFirewallRules,omitempty" yaml:"totalFirewallRules,omitempty"`
	// RulesByInterface maps interface names to their firewall rule counts.
	RulesByInterface map[string]int `json:"rulesByInterface,omitempty" yaml:"rulesByInterface,omitempty"`
	// RulesByType maps rule types (pass, block, reject) to their counts.
	RulesByType map[string]int `json:"rulesByType,omitempty" yaml:"rulesByType,omitempty"`
	// NATEntries is the total number of NAT rules (inbound and outbound).
	NATEntries int `json:"natEntries,omitempty" yaml:"natEntries,omitempty"`
	// NATMode is the outbound NAT mode.
	NATMode string `json:"natMode,omitempty" yaml:"natMode,omitempty"`

	// TotalGateways is the total number of configured gateways.
	TotalGateways int `json:"totalGateways,omitempty" yaml:"totalGateways,omitempty"`
	// TotalGatewayGroups is the total number of gateway groups.
	TotalGatewayGroups int `json:"totalGatewayGroups,omitempty" yaml:"totalGatewayGroups,omitempty"`

	// DHCPScopes is the total number of DHCP scopes.
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

// DeadRuleFinding represents a dead rule finding.
type DeadRuleFinding struct {
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
	// Issue is a brief summary of the security issue.
	Issue string `json:"issue,omitempty" yaml:"issue,omitempty"`
	// Severity is the severity level (e.g., "critical", "high", "medium", "low").
	Severity string `json:"severity,omitempty" yaml:"severity,omitempty"`
	// Description is a detailed explanation of the security issue.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Recommendation is the suggested corrective action.
	Recommendation string `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
}

// PerformanceFinding represents a performance finding.
type PerformanceFinding struct {
	// Component is the configuration component affected by the finding.
	Component string `json:"component,omitempty" yaml:"component,omitempty"`
	// Issue is a brief summary of the performance issue.
	Issue string `json:"issue,omitempty" yaml:"issue,omitempty"`
	// Severity is the severity level.
	Severity string `json:"severity,omitempty" yaml:"severity,omitempty"`
	// Description is a detailed explanation of the performance issue.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Recommendation is the suggested corrective action.
	Recommendation string `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
}

// ConsistencyFinding represents a consistency finding.
type ConsistencyFinding struct {
	// Component is the configuration component affected by the finding.
	Component string `json:"component,omitempty" yaml:"component,omitempty"`
	// Issue is a brief summary of the consistency issue.
	Issue string `json:"issue,omitempty" yaml:"issue,omitempty"`
	// Severity is the severity level.
	Severity string `json:"severity,omitempty" yaml:"severity,omitempty"`
	// Description is a detailed explanation of the consistency issue.
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

// ComplianceChecks contains compliance check results.
type ComplianceChecks struct {
	// ComplianceScore is the overall compliance score (0-100).
	ComplianceScore int `json:"complianceScore,omitempty" yaml:"complianceScore,omitempty"`
	// ComplianceItems lists the compliance controls that passed.
	ComplianceItems []string `json:"complianceItems,omitempty" yaml:"complianceItems,omitempty"`
	// Violations lists the compliance controls that failed.
	Violations []string `json:"violations,omitempty" yaml:"violations,omitempty"`
}
