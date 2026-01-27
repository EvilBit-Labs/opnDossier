// Package markdown provides an extended API for generating markdown documentation
// from OPNsense configurations with configurable options and pluggable templates.
package markdown

import (
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
)

// Generator interface for creating documentation in various formats.
type Generator = converter.Generator

// NewMarkdownGenerator creates a new Generator that produces documentation in Markdown, JSON, or YAML formats.
//
// Deprecated: use converter.NewMarkdownGenerator instead.
func NewMarkdownGenerator(logger *log.Logger, opts Options) (Generator, error) {
	return converter.NewMarkdownGenerator(logger, opts)
}

// NewMarkdownGeneratorWithTemplates creates a new Generator with custom template directory support.
//
// Deprecated: use converter.NewMarkdownGeneratorWithTemplates instead.
func NewMarkdownGeneratorWithTemplates(logger *log.Logger, templateDir string, opts Options) (Generator, error) {
	return converter.NewMarkdownGeneratorWithTemplates(logger, templateDir, opts)
}
