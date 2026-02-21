// Package converter provides functionality to convert device configurations to various formats.
package converter

import (
	"context"
	"fmt"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"gopkg.in/yaml.v3"
)

// YAMLConverter is a YAML converter for device configurations.
type YAMLConverter struct{}

// NewYAMLConverter creates and returns a new YAMLConverter for transforming device configurations to YAML format.
func NewYAMLConverter() *YAMLConverter {
	return &YAMLConverter{}
}

// ToYAML converts a device configuration to YAML.
func (c *YAMLConverter) ToYAML(_ context.Context, data *common.CommonDevice) (string, error) {
	if data == nil {
		return "", ErrNilDevice
	}

	target := prepareForExport(data)

	// Marshal the CommonDevice struct to YAML
	yamlBytes, err := yaml.Marshal(target)
	if err != nil {
		return "", fmt.Errorf("failed to marshal to YAML: %w", err)
	}

	return string(yamlBytes), nil
}
