// Package markdown provides an extended API for generating markdown documentation
// from OPNsense configurations with configurable options.
package markdown

import (
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
)

// ReportBuilder defines the interface for building markdown reports.
type ReportBuilder = builder.ReportBuilder

// HybridGenerator provides programmatic markdown, JSON, and YAML generation.
type HybridGenerator = converter.HybridGenerator

// NewHybridGenerator creates a new HybridGenerator with the specified builder.
//
// NewHybridGenerator creates a new HybridGenerator configured with the given ReportBuilder and logger.
// Deprecated: use converter.NewHybridGenerator instead.
// Returns the created HybridGenerator or an error encountered during construction.
func NewHybridGenerator(reportBuilder builder.ReportBuilder, logger *log.Logger) (*HybridGenerator, error) {
	return converter.NewHybridGenerator(reportBuilder, logger)
}