// Package markdown provides an extended API for generating markdown documentation
// from OPNsense configurations with configurable options and pluggable templates.
package markdown

import (
	"text/template"

	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
)

// ReportBuilder defines the interface for building markdown reports.
type ReportBuilder = builder.ReportBuilder

// HybridGenerator provides dual-mode support for markdown generation.
type HybridGenerator = converter.HybridGenerator

// NewHybridGenerator creates a new HybridGenerator with the specified builder and optional template.
//
// Deprecated: use converter.NewHybridGenerator instead.
func NewHybridGenerator(reportBuilder builder.ReportBuilder, logger *log.Logger) (*HybridGenerator, error) {
	return converter.NewHybridGenerator(reportBuilder, logger)
}

// NewHybridGeneratorWithTemplate creates a new HybridGenerator with a custom template override.
//
// Deprecated: use converter.NewHybridGeneratorWithTemplate instead.
func NewHybridGeneratorWithTemplate(
	reportBuilder builder.ReportBuilder,
	tmpl *template.Template,
	logger *log.Logger,
) (*HybridGenerator, error) {
	return converter.NewHybridGeneratorWithTemplate(reportBuilder, tmpl, logger)
}
