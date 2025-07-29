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

// NewConverterAdapter returns a new ConverterAdapter using a default Generator and default options.
// It returns an error if the Generator cannot be created.
func NewConverterAdapter() (*ConverterAdapter, error) {
	generator, err := NewMarkdownGenerator()
	if err != nil {
		return nil, err
	}
	return &ConverterAdapter{
		generator: generator,
		opts:      DefaultOptions(),
	}, nil
}

// NewConverterAdapterWithOptions returns a new ConverterAdapter using the provided options.
// It initializes the underlying markdown generator and returns an error if generator creation fails.
func NewConverterAdapterWithOptions(opts Options) (*ConverterAdapter, error) {
	generator, err := NewMarkdownGenerator()
	if err != nil {
		return nil, err
	}
	return &ConverterAdapter{
		generator: generator,
		opts:      opts,
	}, nil
}

// ToMarkdown converts an OPNsense configuration to markdown using the new Generator API.
// This method implements the converter.Converter interface.
func (a *ConverterAdapter) ToMarkdown(ctx context.Context, opnsense *model.OpnSenseDocument) (string, error) {
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
