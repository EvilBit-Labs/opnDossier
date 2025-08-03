package markdown

import (
	"context"
	"fmt"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// Adapter provides a simplified interface for generating documentation.
type Adapter struct {
	generator Generator
}

// NewAdapter creates a new adapter with the default markdown generator.
func NewAdapter() (*Adapter, error) {
	generator, err := NewMarkdownGenerator(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create markdown generator: %w", err)
	}

	return &Adapter{generator: generator}, nil
}

// GenerateMarkdown generates markdown documentation from an OPNsense configuration.
func (a *Adapter) GenerateMarkdown(
	ctx context.Context,
	cfg *model.OpnSenseDocument,
	comprehensive bool,
) (string, error) {
	opts := DefaultOptions().
		WithFormat(FormatMarkdown).
		WithComprehensive(comprehensive)

	return a.generator.Generate(ctx, cfg, opts)
}

// GenerateJSON generates JSON documentation from an OPNsense configuration.
func (a *Adapter) GenerateJSON(ctx context.Context, cfg *model.OpnSenseDocument) (string, error) {
	opts := DefaultOptions().WithFormat(FormatJSON)

	return a.generator.Generate(ctx, cfg, opts)
}

// GenerateYAML generates YAML documentation from an OPNsense configuration.
func (a *Adapter) GenerateYAML(ctx context.Context, cfg *model.OpnSenseDocument) (string, error) {
	opts := DefaultOptions().WithFormat(FormatYAML)

	return a.generator.Generate(ctx, cfg, opts)
}
