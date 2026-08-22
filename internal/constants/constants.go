// Package constants defines shared constants used across the application.
package constants

import (
	"slices"
	"time"
)

// Version is the current application version, injected at build time by GoReleaser via ldflags.
var Version = "dev"

// Application constants.
const (
	// AppName is the application name used in CLI output and configuration.
	AppName = "opnDossier"

	// DefaultFormat is the default output format for configuration reports.
	DefaultFormat = "markdown"
	// DefaultMode is the default audit report mode.
	DefaultMode = "blue"
	// ConfigFileName is the default configuration file name.
	ConfigFileName = "opndossier.yaml"

	// NetworkAny represents the "any" network in firewall rules.
	NetworkAny = "any"

	// ProtocolHTTPS represents the HTTPS protocol identifier.
	ProtocolHTTPS = "https"

	// FindingTypeSecurity identifies security-related audit findings.
	FindingTypeSecurity = "security"
	// FindingTypeCompliance identifies findings raised against a compliance control.
	FindingTypeCompliance = "compliance"
	// FindingTypeInventory identifies informational inventory findings. These are
	// excluded from the compliance map and rendered as configuration notes rather
	// than security findings.
	FindingTypeInventory = "inventory"
	// FindingTypePerformance identifies performance-related findings.
	FindingTypePerformance = "performance"
	// FindingTypeHygiene identifies configuration-hygiene observations.
	FindingTypeHygiene = "hygiene"
	// FindingTypeWANExposedService identifies a red-mode finding for a management
	// service reachable from the WAN.
	FindingTypeWANExposedService = "wan-exposed-service"
	// FindingTypePortForward identifies a red-mode finding for an inbound NAT
	// port forward.
	FindingTypePortForward = "port-forward"
	// FindingTypeConfigWeakness identifies a red-mode finding for a configuration
	// weakness reframed as attack surface.
	FindingTypeConfigWeakness = "config-weakness"
	// FindingTypeConfiguration identifies findings about missing or malformed
	// configuration values.
	FindingTypeConfiguration = "configuration"
	// FindingTypeValidation identifies findings raised by schema validation.
	FindingTypeValidation = "validation"
	// FindingTypeMaintenance identifies maintainability findings such as
	// undocumented rules.
	FindingTypeMaintenance = "maintenance"
	// FindingTypeUI identifies findings about presentation or theme settings.
	FindingTypeUI = "ui"
	// FindingTypeDuplicateRule identifies a firewall rule duplicated by an
	// earlier rule.
	FindingTypeDuplicateRule = "duplicate-rule"
	// FindingTypeDeadRule identifies a firewall rule shadowed into
	// unreachability.
	FindingTypeDeadRule = "dead-rule"
	// FindingTypeUnusedInterface identifies a configured but unreferenced
	// interface.
	FindingTypeUnusedInterface = "unused-interface"
	// FindingTypeConsistency identifies cross-section configuration
	// inconsistencies.
	FindingTypeConsistency = "consistency"

	// ThemeLight specifies the light color theme for terminal output.
	ThemeLight = "light"
	// ThemeDark specifies the dark color theme for terminal output.
	ThemeDark = "dark"

	// StatusNotEnabled is the display string for disabled features.
	StatusNotEnabled = "❌"
	// StatusEnabled is the display string for enabled features.
	StatusEnabled = "✅"

	// NoConfigAvailable is the placeholder text when configuration data is missing.
	NoConfigAvailable = "*No configuration available*"

	// ProgressRenderingMarkdown is the progress percentage assigned to markdown rendering.
	ProgressRenderingMarkdown = 0.5

	// ConfigThreshold is the detection threshold for configuration presence.
	ConfigThreshold = 0.3

	// DefaultProcessingTimeout is the maximum time allowed for standard processing operations.
	DefaultProcessingTimeout = 5 * time.Minute
	// QuickProcessingTimeout is the maximum time allowed for lightweight processing operations.
	QuickProcessingTimeout = 10 * time.Second

	// SecurityFeatureMultiplier is the scoring weight applied per security feature.
	SecurityFeatureMultiplier = 10
	// MaxSecurityScore is the maximum achievable security score.
	MaxSecurityScore = 100
	// MaxComplexityScore is the maximum achievable complexity score.
	MaxComplexityScore = 100

	// InterfaceComplexityWeight is the complexity scoring weight per network interface.
	InterfaceComplexityWeight = 5
	// FirewallRuleComplexityWeight is the complexity scoring weight per firewall rule.
	FirewallRuleComplexityWeight = 2
	// UserComplexityWeight is the complexity scoring weight per user account.
	UserComplexityWeight = 3
	// GroupComplexityWeight is the complexity scoring weight per user group.
	GroupComplexityWeight = 3
	// SysctlComplexityWeight is the complexity scoring weight per sysctl tunable.
	SysctlComplexityWeight = 4
	// ServiceComplexityWeight is the complexity scoring weight per enabled service.
	ServiceComplexityWeight = 6
	// DHCPComplexityWeight is the complexity scoring weight per DHCP scope.
	DHCPComplexityWeight = 4
	// LoadBalancerComplexityWeight is the complexity scoring weight per load balancer monitor.
	LoadBalancerComplexityWeight = 8
	// GatewayComplexityWeight is the complexity scoring weight per gateway.
	GatewayComplexityWeight = 3
	// GatewayGroupComplexityWeight is the complexity scoring weight per gateway group.
	GatewayGroupComplexityWeight = 5

	// LargeRuleCountThreshold is the firewall rule count above which a configuration is considered large.
	LargeRuleCountThreshold = 100
	// MaxReasonableComplexity is the upper bound for meaningful complexity scores.
	MaxReasonableComplexity = 1000

	// MaxHostnameLength is the RFC 1035 maximum hostname length.
	MaxHostnameLength = 253
	// MinPort is the minimum valid TCP/UDP port number.
	MinPort = 1
	// MaxPort is the maximum valid TCP/UDP port number.
	MaxPort = 65535
	// MaxIPv4Subnet is the maximum IPv4 subnet prefix length.
	MaxIPv4Subnet = 32
	// MaxIPv6Subnet is the maximum IPv6 subnet prefix length.
	MaxIPv6Subnet = 128
	// MinMTU is the minimum valid MTU (RFC 791 minimum for IPv4).
	MinMTU = 68
	// MaxMTU is the maximum valid MTU (jumbo frame).
	MaxMTU = 9000
)

// ValidOptimizationModes defines the allowed system optimization modes.
// Single source of truth for the validator package.
var ValidOptimizationModes = map[string]struct{}{
	"normal":       {},
	"high-latency": {},
	"aggressive":   {},
	"conservative": {},
}

// ValidPowerdModes defines the allowed powerd power modes.
// Single source of truth for the validator package.
var ValidPowerdModes = map[string]struct{}{
	"hadp":       {},
	"hiadp":      {},
	"hadaptive":  {},
	"hiadaptive": {},
	"adaptive":   {},
	"minimum":    {},
	"maximum":    {},
}

// ValidFindingTypes returns a fresh copy of every recognized finding Type value.
// Returns a new slice each call to prevent callers from mutating shared state.
func ValidFindingTypes() []string {
	return []string{
		FindingTypeSecurity,
		FindingTypeCompliance,
		FindingTypeInventory,
		FindingTypePerformance,
		FindingTypeHygiene,
		FindingTypeWANExposedService,
		FindingTypePortForward,
		FindingTypeConfigWeakness,
		FindingTypeConfiguration,
		FindingTypeValidation,
		FindingTypeMaintenance,
		FindingTypeUI,
		FindingTypeDuplicateRule,
		FindingTypeDeadRule,
		FindingTypeUnusedInterface,
		FindingTypeConsistency,
	}
}

// IsValidFindingType reports whether t is a recognized finding Type.
//
// Finding.Type is an untyped string accepted from any compliance plugin,
// including dynamically loaded ones, and nothing validates it at a parse
// boundary. Callers that route on Type should use this to surface an
// unrecognized value rather than silently taking a default branch.
func IsValidFindingType(t string) bool {
	return slices.Contains(ValidFindingTypes(), t)
}
