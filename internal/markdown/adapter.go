package markdown

import (
	"context"

	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// ConverterAdapter adapts the new markdown.Generator interface
// to work with the existing converter.Converter interface, maintaining backward compatibility.
type ConverterAdapter struct {
	generator Generator
	opts      Options
}

// NewConverterAdapter creates a new adapter that wraps the new Generator interface.
func NewConverterAdapter() *ConverterAdapter {
	return &ConverterAdapter{
		generator: NewMarkdownGenerator(),
		opts:      DefaultOptions(),
	}
}

// NewConverterAdapterWithOptions creates a new adapter with custom options.
func NewConverterAdapterWithOptions(opts Options) *ConverterAdapter {
	return &ConverterAdapter{
		generator: NewMarkdownGenerator(),
		opts:      opts,
	}
}

// ToMarkdown converts an OPNsense configuration to markdown using the new Generator API.
// This method implements the converter.Converter interface.
func (a *ConverterAdapter) ToMarkdown(ctx context.Context, opnsense *model.Opnsense) (string, error) {
	return a.generator.Generate(ctx, opnsense, a.opts)
}

// SetOptions allows changing the options after creation.
func (a *ConverterAdapter) SetOptions(opts Options) {
	a.opts = opts
}

// GetOptions returns the current options.
func (a *ConverterAdapter) GetOptions() Options {
	return a.opts
}
