package converter

import (
	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// ReportBuilder provides compatibility for legacy converter package callers.
//
// Deprecated: use builder.ReportBuilder instead.
type ReportBuilder = builder.ReportBuilder

// MarkdownBuilder provides compatibility for legacy converter package callers.
//
// Deprecated: use builder.MarkdownBuilder instead.
type MarkdownBuilder = builder.MarkdownBuilder

// NewMarkdownBuilder creates a new MarkdownBuilder instance.
//
// Deprecated: use builder.NewMarkdownBuilder instead.
func NewMarkdownBuilder() *builder.MarkdownBuilder {
	return builder.NewMarkdownBuilder()
}

// NewMarkdownBuilderWithOptions creates a new MarkdownBuilder with custom options.
//
// Deprecated: use builder.NewMarkdownBuilderWithOptions instead.
// Note: opts parameter is ignored as builder no longer uses Options.
func NewMarkdownBuilderWithOptions(
	config *model.OpnSenseDocument,
	_ Options,
	logger *log.Logger,
) *builder.MarkdownBuilder {
	return builder.NewMarkdownBuilderWithOptions(config, builder.Options{}, logger)
}

// formatBoolean provides legacy compatibility for markdown table formatting.
func formatBoolean(value string) string {
	return formatters.FormatBoolean(value)
}

// formatBooleanInverted provides legacy compatibility for inverted boolean formatting.
func formatBooleanInverted(value string) string {
	return formatters.FormatBooleanInverted(value)
}

// formatIntBoolean provides legacy compatibility for integer boolean formatting.
func formatIntBoolean(value int) string {
	return formatters.FormatIntBoolean(value)
}

// formatIntBooleanWithUnset provides legacy compatibility for integer boolean formatting with unset support.
func formatIntBooleanWithUnset(value int) string {
	return formatters.FormatIntBooleanWithUnset(value)
}

// formatStructBoolean provides legacy compatibility for struct boolean formatting.
func formatStructBoolean(value struct{}) string {
	return formatters.FormatStructBoolean(value)
}

// formatBool provides legacy compatibility for boolean formatting.
func formatBool(value bool) string {
	return formatters.FormatBool(value)
}

// getPowerModeDescription provides legacy compatibility for power mode descriptions.
func getPowerModeDescription(mode string) string {
	return formatters.GetPowerModeDescriptionCompact(mode)
}
