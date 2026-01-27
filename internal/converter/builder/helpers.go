package builder

import (
	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
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
