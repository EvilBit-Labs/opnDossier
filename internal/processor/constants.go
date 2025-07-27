package processor

import "time"

// String constants.
const (
	// Network constants.
	NetworkAny = "any"

	// Protocol constants.
	ProtocolHTTPS = "https"

	// Finding types.
	FindingTypeSecurity = "security"
)

// Numeric constants.
const (
	// Timeout constants.
	DefaultProcessingTimeout = 5 * time.Minute
	QuickProcessingTimeout   = 10 * time.Second

	// Scoring constants.
	SecurityFeatureMultiplier = 10
	MaxSecurityScore          = 100
	MaxComplexityScore        = 100

	// Complexity scoring weights.
	InterfaceComplexityWeight    = 5
	FirewallRuleComplexityWeight = 2
	UserComplexityWeight         = 3
	GroupComplexityWeight        = 3
	SysctlComplexityWeight       = 4
	ServiceComplexityWeight      = 6
	DHCPComplexityWeight         = 4
	LoadBalancerComplexityWeight = 8

	// Thresholds.
	LargeRuleCountThreshold = 100
	MaxReasonableComplexity = 1000
)
