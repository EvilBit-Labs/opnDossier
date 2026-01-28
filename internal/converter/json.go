// Package converter provides functionality to convert OPNsense configurations to various formats.
package converter

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// JSONConverter is a JSON converter for OPNsense configurations.
type JSONConverter struct{}

// NewJSONConverter creates and returns a new JSONConverter for converting OPNsense configurations to JSON format.
func NewJSONConverter() *JSONConverter {
	return &JSONConverter{}
}

// ToJSON converts an OPNsense configuration to JSON.
func (c *JSONConverter) ToJSON(_ context.Context, opnsense *model.OpnSenseDocument) (string, error) {
	if opnsense == nil {
		return "", ErrNilOpnSenseDocument
	}

	// Marshal the OpnSenseDocument struct to JSON with indentation
	jsonBytes, err := json.MarshalIndent(opnsense, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal to JSON: %w", err)
	}

	return string(jsonBytes), nil
}
