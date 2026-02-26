// Package converter provides functionality to convert device configurations to various formats.
package converter

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// JSONConverter is a JSON converter for device configurations.
type JSONConverter struct{}

// NewJSONConverter creates and returns a new JSONConverter for converting device configurations to JSON format.
func NewJSONConverter() *JSONConverter {
	return &JSONConverter{}
}

// ToJSON converts a device configuration to JSON.
// When redact is true, sensitive fields (passwords, private keys, community strings)
// are replaced with [REDACTED] in the output.
func (c *JSONConverter) ToJSON(_ context.Context, data *common.CommonDevice, redact bool) (string, error) {
	if data == nil {
		return "", ErrNilDevice
	}

	target := prepareForExport(data, redact)

	// Marshal the CommonDevice struct to JSON with indentation
	jsonBytes, err := json.MarshalIndent(target, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal to JSON: %w", err)
	}

	return string(jsonBytes), nil
}
