package compliance_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/stretchr/testify/assert"
)

func TestErrors(t *testing.T) {
	t.Parallel()

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
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestControlStruct(t *testing.T) {
	t.Parallel()

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
			t.Parallel()
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
	t.Parallel()

	finding := compliance.Finding{
		Type:           "compliance",
		Severity:       "high",
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
		{"Severity", "Severity", "high"},
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
			t.Parallel()
			switch tt.field {
			case "Type":
				assert.Equal(t, tt.expected, finding.Type)
			case "Severity":
				assert.Equal(t, tt.expected, finding.Severity)
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

func TestCloneControl_MutationIndependence(t *testing.T) {
	t.Parallel()

	original := compliance.Control{
		ID:          "TEST-001",
		Title:       "Original Title",
		Description: "Original description",
		Category:    "Test",
		Severity:    "high",
		References:  []string{"REF-001", "REF-002"},
		Tags:        []string{"tag1", "tag2"},
		Metadata:    map[string]string{"key1": "val1", "key2": "val2"},
	}

	clone := compliance.CloneControl(original)

	// Mutate the clone
	clone.References = append(clone.References, "REF-NEW")
	clone.Tags = append(clone.Tags, "tag-new")
	clone.Metadata["key3"] = "val3"

	// Original must be unaffected
	assert.Len(t, original.References, 2, "original References should not be mutated")
	assert.Len(t, original.Tags, 2, "original Tags should not be mutated")
	assert.Len(t, original.Metadata, 2, "original Metadata should not be mutated")
	_, hasKey3 := original.Metadata["key3"]
	assert.False(t, hasKey3, "original Metadata should not contain cloned key")
}

func TestCloneControls_MutationIndependence(t *testing.T) {
	t.Parallel()

	originals := []compliance.Control{
		{
			ID:         "CTRL-001",
			Severity:   "critical",
			References: []string{"REF-A"},
			Tags:       []string{"t1"},
			Metadata:   map[string]string{"k": "v"},
		},
		{
			ID:         "CTRL-002",
			Severity:   "low",
			References: []string{"REF-B"},
			Tags:       []string{"t2"},
			Metadata:   map[string]string{"k2": "v2"},
		},
	}

	clones := compliance.CloneControls(originals)
	assert.Len(t, clones, 2)

	// Mutate first clone
	clones[0].References = append(clones[0].References, "REF-MUTATED")
	clones[0].Tags = append(clones[0].Tags, "mutated")
	clones[0].Metadata["mutated"] = "yes"

	// Originals unaffected
	assert.Len(t, originals[0].References, 1)
	assert.Len(t, originals[0].Tags, 1)
	assert.Len(t, originals[0].Metadata, 1)
}

func TestFindingValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		finding compliance.Finding
		isValid bool
	}{
		{
			name: "Valid finding",
			finding: compliance.Finding{
				Type:           "compliance",
				Severity:       "high",
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
				Severity:       "high",
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
				Severity:       "high",
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
			name: "Missing severity is invalid",
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
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			isValid := tt.finding.Type != "" &&
				tt.finding.Severity != "" &&
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
