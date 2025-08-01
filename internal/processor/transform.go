package processor

import (
	"context"
	"fmt"

	"github.com/unclesp1d3r/opnFocus/internal/markdown"
	"gopkg.in/yaml.v3"
)

// toYAML converts a report to YAML format.
func (p *CoreProcessor) toYAML(report *Report) (string, error) {
	data, err := yaml.Marshal(report) //nolint:musttag // Report has proper yaml tags
	if err != nil {
		return "", fmt.Errorf("failed to marshal report to YAML: %w", err)
	}

	return string(data), nil
}

// toMarkdown converts a report to markdown using the configured converter.
func (p *CoreProcessor) toMarkdown(ctx context.Context, report *Report) (string, error) {
	if report.NormalizedConfig == nil {
		return "", ErrNormalizedConfigUnavailable
	}

	// Use the existing markdown generator to convert the configuration
	configMarkdown, err := p.generator.Generate(ctx, report.NormalizedConfig, markdown.DefaultOptions())
	if err != nil {
		return "", fmt.Errorf("failed to convert configuration to markdown: %w", err)
	}

	// Also include the report's markdown representation
	reportMarkdown := report.ToMarkdown()

	// Combine both markdown outputs
	combined := fmt.Sprintf("%s\n\n%s", configMarkdown, reportMarkdown)

	return combined, nil
}
