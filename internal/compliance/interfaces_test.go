package compliance_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/stretchr/testify/assert"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrPluginNotFound",
			err:      compliance.ErrPluginNotFound,
			expected: "plugin not found",
		},
		{
			name:     "ErrControlNotFound",
			err:      compliance.ErrControlNotFound,
			expected: "control not found",
		},
		{
			name:     "ErrNoControlsDefined",
			err:      compliance.ErrNoControlsDefined,
			expected: "no controls defined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestControlStruct(t *testing.T) {
	control := compliance.Control{
		ID:          "TEST-001",
		Title:       "Test Control",
		Description: "Test description",
		Category:    "Test Category",
		Severity:    "high",
		Rationale:   "Test rationale",
		Remediation: "Test remediation",
		Tags:        []string{"test", "control"},
	}

	tests := []struct {
		name     string
		field    string
		expected any
	}{
		{"ID", "ID", "TEST-001"},
		{"Title", "Title", "Test Control"},
		{"Description", "Description", "Test description"},
		{"Category", "Category", "Test Category"},
		{"Severity", "Severity", "high"},
		{"Rationale", "Rationale", "Test rationale"},
		{"Remediation", "Remediation", "Test remediation"},
		{"Tags length", "Tags", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.field {
			case "ID":
				assert.Equal(t, tt.expected, control.ID)
			case "Title":
				assert.Equal(t, tt.expected, control.Title)
			case "Description":
				assert.Equal(t, tt.expected, control.Description)
			case "Category":
				assert.Equal(t, tt.expected, control.Category)
			case "Severity":
				assert.Equal(t, tt.expected, control.Severity)
			case "Rationale":
				assert.Equal(t, tt.expected, control.Rationale)
			case "Remediation":
				assert.Equal(t, tt.expected, control.Remediation)
			case "Tags":
				assert.Len(t, control.Tags, tt.expected.(int)) //nolint:errcheck // Test assertion
			}
		})
	}
}

func TestFindingStruct(t *testing.T) {
	finding := compliance.Finding{
		Type:           "compliance",
		Title:          "Test Finding",
		Description:    "Test description",
		Recommendation: "Test recommendation",
		Component:      "test-component",
		Reference:      "TEST-001",
		References:     []string{"TEST-001", "TEST-002"},
		Tags:           []string{"test", "finding"},
	}

	tests := []struct {
		name     string
		field    string
		expected any
	}{
		{"Type", "Type", "compliance"},
		{"Title", "Title", "Test Finding"},
		{"Description", "Description", "Test description"},
		{"Recommendation", "Recommendation", "Test recommendation"},
		{"Component", "Component", "test-component"},
		{"Reference", "Reference", "TEST-001"},
		{"References length", "References", 2},
		{"Tags length", "Tags", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.field {
			case "Type":
				assert.Equal(t, tt.expected, finding.Type)
			case "Title":
				assert.Equal(t, tt.expected, finding.Title)
			case "Description":
				assert.Equal(t, tt.expected, finding.Description)
			case "Recommendation":
				assert.Equal(t, tt.expected, finding.Recommendation)
			case "Component":
				assert.Equal(t, tt.expected, finding.Component)
			case "Reference":
				assert.Equal(t, tt.expected, finding.Reference)
			case "References":
				assert.Len(t, finding.References, tt.expected.(int)) //nolint:errcheck // Test assertion
			case "Tags":
				assert.Len(t, finding.Tags, tt.expected.(int)) //nolint:errcheck // Test assertion
			}
		})
	}
}

func TestFindingValidation(t *testing.T) {
	tests := []struct {
		name    string
		finding compliance.Finding
		isValid bool
	}{
		{
			name: "Valid finding",
			finding: compliance.Finding{
				Type:           "compliance",
				Title:          "Test Finding",
				Description:    "Test description",
				Recommendation: "Test recommendation",
				Component:      "test-component",
				Reference:      "TEST-001",
				References:     []string{"TEST-001"},
				Tags:           []string{"test"},
			},
			isValid: true,
		},
		{
			name: "Empty type",
			finding: compliance.Finding{
				Title:          "Test Finding",
				Description:    "Test description",
				Recommendation: "Test recommendation",
				Component:      "test-component",
				Reference:      "TEST-001",
				References:     []string{"TEST-001"},
				Tags:           []string{"test"},
			},
			isValid: false,
		},
		{
			name: "Empty title",
			finding: compliance.Finding{
				Type:           "compliance",
				Description:    "Test description",
				Recommendation: "Test recommendation",
				Component:      "test-component",
				Reference:      "TEST-001",
				References:     []string{"TEST-001"},
				Tags:           []string{"test"},
			},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := tt.finding.Type != "" &&
				tt.finding.Title != "" &&
				tt.finding.Description != "" &&
				tt.finding.Recommendation != "" &&
				tt.finding.Component != "" &&
				tt.finding.Reference != "" &&
				len(tt.finding.References) > 0 &&
				len(tt.finding.Tags) > 0
			assert.Equal(t, tt.isValid, isValid)
		})
	}
}
