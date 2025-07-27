package processor

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"
)

// toYAML converts a report to YAML format.
func (p *CoreProcessor) toYAML(report *Report) (string, error) {
	data, err := yaml.Marshal(report)
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

	// Use the existing markdown converter to convert the configuration
	configMarkdown, err := p.converter.ToMarkdown(ctx, report.NormalizedConfig)
	if err != nil {
		return "", fmt.Errorf("failed to convert configuration to markdown: %w", err)
	}

	// Also include the report's markdown representation
	reportMarkdown := report.ToMarkdown()

	// Combine both markdown outputs
	combined := fmt.Sprintf("%s\n\n%s", configMarkdown, reportMarkdown)

	return combined, nil
}
