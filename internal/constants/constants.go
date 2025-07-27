// Package constants defines shared constants used across the application.
package constants

import "time"

// Application constants.
const (
	// Network constants.
	NetworkAny = "any"

	// Protocol constants.
	ProtocolHTTPS = "https"

	// Rule type constants.
	RuleTypePass = "pass"

	// Finding types.
	FindingTypeSecurity = "security"

	// Theme constants.
	ThemeLight = "light"
	ThemeDark  = "dark"

	// Status display constants.
	StatusNotEnabled = "❌"
	StatusEnabled    = "✅"

	// Configuration availability.
	NoConfigAvailable = "*No configuration available*"

	// Progress rendering constants.
	ProgressRenderingMarkdown = 0.5

	// Configuration detection threshold.
	ConfigThreshold = 0.3

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
