// Package converter provides functionality to convert OPNsense configurations to various formats.
package converter

import (
	"context"
	"fmt"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"gopkg.in/yaml.v3"
)

// YAMLConverter is a YAML converter for OPNsense configurations.
type YAMLConverter struct{}

// NewYAMLConverter creates and returns a new YAMLConverter for transforming OPNsense configurations to YAML format.
func NewYAMLConverter() *YAMLConverter {
	return &YAMLConverter{}
}

// ToYAML converts an OPNsense configuration to YAML.
func (c *YAMLConverter) ToYAML(_ context.Context, opnsense *model.OpnSenseDocument) (string, error) {
	if opnsense == nil {
		return "", ErrNilOpnSenseDocument
	}

	// Marshal the OpnSenseDocument struct to YAML
	yamlBytes, err := yaml.Marshal(opnsense) //nolint:musttag // OpnSenseDocument has proper yaml tags
	if err != nil {
		return "", fmt.Errorf("failed to marshal to YAML: %w", err)
	}

	return normalizeLineEndings(string(yamlBytes)), nil
}
