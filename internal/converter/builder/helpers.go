package builder

import (
	"strconv"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// Time unit constants for lease time formatting.
const (
	secondsPerMinute = 60
	secondsPerHour   = 3600
	secondsPerDay    = 86400
	secondsPerWeek   = 604800
)

// EscapeTableContent escapes content for safe display in markdown tables.
func (b *MarkdownBuilder) EscapeTableContent(content any) string {
	return formatters.EscapeTableContent(content)
}

// TruncateDescription truncates a description to the specified maximum length.
func (b *MarkdownBuilder) TruncateDescription(description string, maxLength int) string {
	return formatters.TruncateDescription(description, maxLength)
}

// IsLastInSlice checks if the given index is the last element in a slice or array.
func (b *MarkdownBuilder) IsLastInSlice(index int, slice any) bool {
	return formatters.IsLastInSlice(index, slice)
}

// DefaultValue returns the default value if the primary value is empty.
func (b *MarkdownBuilder) DefaultValue(value, defaultVal any) any {
	return formatters.DefaultValue(value, defaultVal)
}

// IsEmpty checks if a value is considered empty according to Go conventions.
func (b *MarkdownBuilder) IsEmpty(value any) bool {
	return formatters.IsEmpty(value)
}

// ToUpper converts a string to uppercase.
func (b *MarkdownBuilder) ToUpper(s string) string {
	return formatters.ToUpper(s)
}

// ToLower converts a string to lowercase.
func (b *MarkdownBuilder) ToLower(s string) string {
	return formatters.ToLower(s)
}

// TrimSpace removes leading and trailing whitespace from a string.
func (b *MarkdownBuilder) TrimSpace(s string) string {
	return formatters.TrimSpace(s)
}

// BoolToString converts a boolean value to a standardized string representation with emojis.
func (b *MarkdownBuilder) BoolToString(val bool) string {
	return formatters.BoolToString(val)
}

// FormatBytes formats a byte count as a human-readable string.
func (b *MarkdownBuilder) FormatBytes(bytes int64) string {
	return formatters.FormatBytes(bytes)
}

// SanitizeID converts a string to a valid HTML/markdown anchor ID.
func (b *MarkdownBuilder) SanitizeID(s string) string {
	return formatters.SanitizeID(s)
}

// AssessRiskLevel returns a consistent emoji + text representation.
func (b *MarkdownBuilder) AssessRiskLevel(severity string) string {
	return formatters.AssessRiskLevel(severity)
}

// CalculateSecurityScore computes an overall score (0-100).
func (b *MarkdownBuilder) CalculateSecurityScore(data *model.OpnSenseDocument) int {
	return formatters.CalculateSecurityScore(data)
}

// AssessServiceRisk maps common services to risk levels.
func (b *MarkdownBuilder) AssessServiceRisk(service model.Service) string {
	return formatters.AssessServiceRisk(service)
}

// FilterSystemTunables filters system tunables based on security-related prefixes.
func (b *MarkdownBuilder) FilterSystemTunables(tunables []model.SysctlItem, includeTunables bool) []model.SysctlItem {
	return formatters.FilterSystemTunables(tunables, includeTunables)
}

// GroupServicesByStatus groups services by their status (running/stopped).
func (b *MarkdownBuilder) GroupServicesByStatus(services []model.Service) map[string][]model.Service {
	return formatters.GroupServicesByStatus(services)
}

// AggregatePackageStats aggregates statistics about packages.
func (b *MarkdownBuilder) AggregatePackageStats(packages []model.Package) map[string]int {
	return formatters.AggregatePackageStats(packages)
}

// FilterRulesByType filters firewall rules by their type.
func (b *MarkdownBuilder) FilterRulesByType(rules []model.Rule, ruleType string) []model.Rule {
	return formatters.FilterRulesByType(rules, ruleType)
}

// ExtractUniqueValues extracts unique values from a slice of strings.
func (b *MarkdownBuilder) ExtractUniqueValues(items []string) []string {
	return formatters.ExtractUniqueValues(items)
}

// FormatLeaseTime converts DHCP lease time seconds to human-readable format.
// Empty string or "0" returns "-".
// Invalid input returns the original string.
// Examples:
//   - "" → "-"
//   - "0" → "-"
//   - "3600" → "1 hour"
//   - "7200" → "2 hours"
//   - "86400" → "1 day"
//   - "172800" → "2 days"
//   - "604800" → "1 week"
//   - "1209600" → "2 weeks"
//   - "5400" → "1 hour, 30 minutes"
func FormatLeaseTime(seconds string) string {
	if seconds == "" || seconds == "0" {
		return "-"
	}

	secs, err := strconv.Atoi(seconds)
	if err != nil {
		return seconds
	}

	if secs <= 0 {
		return "-"
	}

	return formatDuration(secs)
}

// formatDuration converts seconds to a human-readable duration string.
func formatDuration(totalSeconds int) string {
	if totalSeconds >= secondsPerWeek {
		weeks := totalSeconds / secondsPerWeek
		remainder := totalSeconds % secondsPerWeek
		if remainder == 0 {
			return pluralize(weeks, "week")
		}
		return pluralize(weeks, "week") + ", " + formatDuration(remainder)
	}

	if totalSeconds >= secondsPerDay {
		days := totalSeconds / secondsPerDay
		remainder := totalSeconds % secondsPerDay
		if remainder == 0 {
			return pluralize(days, "day")
		}
		return pluralize(days, "day") + ", " + formatDuration(remainder)
	}

	if totalSeconds >= secondsPerHour {
		hours := totalSeconds / secondsPerHour
		remainder := totalSeconds % secondsPerHour
		if remainder == 0 {
			return pluralize(hours, "hour")
		}
		return pluralize(hours, "hour") + ", " + formatDuration(remainder)
	}

	if totalSeconds >= secondsPerMinute {
		minutes := totalSeconds / secondsPerMinute
		remainder := totalSeconds % secondsPerMinute
		if remainder == 0 {
			return pluralize(minutes, "minute")
		}
		return pluralize(minutes, "minute") + ", " + pluralize(remainder, "second")
	}

	return pluralize(totalSeconds, "second")
}

// pluralize returns the singular or plural form of a unit based on the count.
func pluralize(count int, unit string) string {
	if count == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(count) + " " + unit + "s"
}

// HasAdvancedDHCPConfig checks if any AdvDHCP* fields are populated in a DhcpdInterface.
// This includes: AliasAddress, AliasSubnet, DHCPRejectFrom, and all AdvDHCP* fields.
func HasAdvancedDHCPConfig(dhcp model.DhcpdInterface) bool {
	// Check alias fields
	if dhcp.AliasAddress != "" || dhcp.AliasSubnet != "" || dhcp.DHCPRejectFrom != "" {
		return true
	}

	// Check all AdvDHCP* fields (14 total)
	return dhcp.AdvDHCPPTTimeout != "" ||
		dhcp.AdvDHCPPTRetry != "" ||
		dhcp.AdvDHCPPTSelectTimeout != "" ||
		dhcp.AdvDHCPPTReboot != "" ||
		dhcp.AdvDHCPPTBackoffCutoff != "" ||
		dhcp.AdvDHCPPTInitialInterval != "" ||
		dhcp.AdvDHCPPTValues != "" ||
		dhcp.AdvDHCPSendOptions != "" ||
		dhcp.AdvDHCPRequestOptions != "" ||
		dhcp.AdvDHCPRequiredOptions != "" ||
		dhcp.AdvDHCPOptionModifiers != "" ||
		dhcp.AdvDHCPConfigAdvanced != "" ||
		dhcp.AdvDHCPConfigFileOverride != "" ||
		dhcp.AdvDHCPConfigFileOverridePath != ""
}

// HasDHCPv6Config checks if any DHCPv6 fields are populated in a DhcpdInterface.
// This includes: Track6Interface, Track6PrefixID, and all AdvDHCP6* fields.
func HasDHCPv6Config(dhcp model.DhcpdInterface) bool {
	// Check Track6 fields
	if dhcp.Track6Interface != "" || dhcp.Track6PrefixID != "" {
		return true
	}

	// Check all AdvDHCP6* fields (26 total)
	return dhcp.AdvDHCP6InterfaceStatementSendOptions != "" ||
		dhcp.AdvDHCP6InterfaceStatementRequestOptions != "" ||
		dhcp.AdvDHCP6InterfaceStatementInformationOnlyEnable != "" ||
		dhcp.AdvDHCP6InterfaceStatementScript != "" ||
		dhcp.AdvDHCP6IDAssocStatementAddressEnable != "" ||
		dhcp.AdvDHCP6IDAssocStatementAddress != "" ||
		dhcp.AdvDHCP6IDAssocStatementAddressID != "" ||
		dhcp.AdvDHCP6IDAssocStatementAddressPLTime != "" ||
		dhcp.AdvDHCP6IDAssocStatementAddressVLTime != "" ||
		dhcp.AdvDHCP6IDAssocStatementPrefixEnable != "" ||
		dhcp.AdvDHCP6IDAssocStatementPrefix != "" ||
		dhcp.AdvDHCP6IDAssocStatementPrefixID != "" ||
		dhcp.AdvDHCP6IDAssocStatementPrefixPLTime != "" ||
		dhcp.AdvDHCP6IDAssocStatementPrefixVLTime != "" ||
		dhcp.AdvDHCP6PrefixInterfaceStatementSLALen != "" ||
		dhcp.AdvDHCP6AuthenticationStatementAuthName != "" ||
		dhcp.AdvDHCP6AuthenticationStatementProtocol != "" ||
		dhcp.AdvDHCP6AuthenticationStatementAlgorithm != "" ||
		dhcp.AdvDHCP6AuthenticationStatementRDM != "" ||
		dhcp.AdvDHCP6KeyInfoStatementKeyName != "" ||
		dhcp.AdvDHCP6KeyInfoStatementRealm != "" ||
		dhcp.AdvDHCP6KeyInfoStatementKeyID != "" ||
		dhcp.AdvDHCP6KeyInfoStatementSecret != "" ||
		dhcp.AdvDHCP6KeyInfoStatementExpire != "" ||
		dhcp.AdvDHCP6ConfigAdvanced != "" ||
		dhcp.AdvDHCP6ConfigFileOverride != "" ||
		dhcp.AdvDHCP6ConfigFileOverridePath != ""
}
