// Package constants defines shared constants used across the application.
package constants

import "time"

// Version information.
var Version = "1.0.0"

// Application constants.
const (
	// Application metadata.
	AppName = "opnDossier"

	// Default configuration values.
	DefaultFormat  = "markdown"
	DefaultMode    = "standard"
	ConfigFileName = "opndossier.yaml"

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
	GatewayComplexityWeight      = 3
	GatewayGroupComplexityWeight = 5

	// Thresholds.
	LargeRuleCountThreshold = 100
	MaxReasonableComplexity = 1000

	// Template file paths - relative to internal/templates/
	// Main templates - used by convert/display commands (standard templates).
	TemplateOpnSenseReportComprehensive = "opnsense_report_comprehensive.md.tmpl" // Used with --comprehensive flag
	TemplateOpnSenseReport              = "opnsense_report.md.tmpl"               // Default template for convert/display

	// Report templates in reports/ subdirectory - used by audit function.
	TemplateStandardReport     = "reports/standard.md.tmpl"      // Audit mode: standard
	TemplateBlueReport         = "reports/blue.md.tmpl"          // Audit mode: blue
	TemplateRedReport          = "reports/red.md.tmpl"           // Audit mode: red
	TemplateBlueEnhancedReport = "reports/blue_enhanced.md.tmpl" // Audit mode: blue-enhanced
)
