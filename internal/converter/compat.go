package converter

import (
	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
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

// NewMarkdownBuilderWithConfig creates a new MarkdownBuilder with configuration.
//
// Deprecated: use builder.NewMarkdownBuilderWithConfig instead.
func NewMarkdownBuilderWithConfig(
	config *common.CommonDevice,
	logger *logging.Logger,
) *builder.MarkdownBuilder {
	return builder.NewMarkdownBuilderWithConfig(config, logger)
}
