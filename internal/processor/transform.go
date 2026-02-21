package processor

import (
	"context"
	"fmt"

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

// toMarkdown converts a report to markdown format.
func (p *CoreProcessor) toMarkdown(_ context.Context, report *Report) (string, error) {
	if report.NormalizedConfig == nil {
		return "", ErrNormalizedConfigUnavailable
	}

	return report.ToMarkdown(), nil
}
