package analysis_test

import (
	"encoding/json"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeverityConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		severity analysis.Severity
		expected string
	}{
		{name: "critical", severity: analysis.SeverityCritical, expected: "critical"},
		{name: "high", severity: analysis.SeverityHigh, expected: "high"},
		{name: "medium", severity: analysis.SeverityMedium, expected: "medium"},
		{name: "low", severity: analysis.SeverityLow, expected: "low"},
		{name: "info", severity: analysis.SeverityInfo, expected: "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, string(tt.severity))
		})
	}
}

func TestSeverityString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		severity analysis.Severity
		expected string
	}{
		{name: "critical string", severity: analysis.SeverityCritical, expected: "critical"},
		{name: "high string", severity: analysis.SeverityHigh, expected: "high"},
		{name: "medium string", severity: analysis.SeverityMedium, expected: "medium"},
		{name: "low string", severity: analysis.SeverityLow, expected: "low"},
		{name: "info string", severity: analysis.SeverityInfo, expected: "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.severity.String())
		})
	}
}

func TestIsValidSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		severity analysis.Severity
		expected bool
	}{
		{name: "critical is valid", severity: analysis.SeverityCritical, expected: true},
		{name: "high is valid", severity: analysis.SeverityHigh, expected: true},
		{name: "medium is valid", severity: analysis.SeverityMedium, expected: true},
		{name: "low is valid", severity: analysis.SeverityLow, expected: true},
		{name: "info is valid", severity: analysis.SeverityInfo, expected: true},
		{name: "empty is invalid", severity: "", expected: false},
		{name: "unknown is invalid", severity: "unknown", expected: false},
		{name: "uppercase HIGH is invalid", severity: "HIGH", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, analysis.IsValidSeverity(tt.severity))
		})
	}
}

func TestValidSeverities(t *testing.T) {
	t.Parallel()

	assert.Len(t, analysis.ValidSeverities(), 5)
	assert.Contains(t, analysis.ValidSeverities(), analysis.SeverityCritical)
	assert.Contains(t, analysis.ValidSeverities(), analysis.SeverityHigh)
	assert.Contains(t, analysis.ValidSeverities(), analysis.SeverityMedium)
	assert.Contains(t, analysis.ValidSeverities(), analysis.SeverityLow)
	assert.Contains(t, analysis.ValidSeverities(), analysis.SeverityInfo)
}

func TestFindingStruct(t *testing.T) {
	t.Parallel()

	finding := analysis.Finding{
		Type:           "compliance",
		Severity:       "high",
		Title:          "Weak firewall rule",
		Description:    "Firewall rule allows unrestricted access",
		Recommendation: "Restrict source addresses",
		Component:      "firewall",
		Reference:      "STIG-V-123456",
		References:     []string{"CIS-1.1", "NIST-800-53"},
		Tags:           []string{"firewall", "access-control"},
		Metadata:       map[string]string{"rule_id": "10", "interface": "wan"},
	}

	tests := []struct {
		name     string
		actual   any
		expected any
	}{
		{name: "Type", actual: finding.Type, expected: "compliance"},
		{name: "Severity", actual: finding.Severity, expected: "high"},
		{name: "Title", actual: finding.Title, expected: "Weak firewall rule"},
		{name: "Description", actual: finding.Description, expected: "Firewall rule allows unrestricted access"},
		{name: "Recommendation", actual: finding.Recommendation, expected: "Restrict source addresses"},
		{name: "Component", actual: finding.Component, expected: "firewall"},
		{name: "Reference", actual: finding.Reference, expected: "STIG-V-123456"},
		{name: "References length", actual: len(finding.References), expected: 2},
		{name: "Tags length", actual: len(finding.Tags), expected: 2},
		{name: "Metadata rule_id", actual: finding.Metadata["rule_id"], expected: "10"},
		{name: "Metadata interface", actual: finding.Metadata["interface"], expected: "wan"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.actual)
		})
	}
}

func TestFindingZeroValue(t *testing.T) {
	t.Parallel()

	var finding analysis.Finding

	assert.Empty(t, finding.Type)
	assert.Empty(t, finding.Severity)
	assert.Empty(t, finding.Title)
	assert.Empty(t, finding.Description)
	assert.Empty(t, finding.Recommendation)
	assert.Empty(t, finding.Component)
	assert.Empty(t, finding.Reference)
	assert.Nil(t, finding.References)
	assert.Nil(t, finding.Tags)
	assert.Nil(t, finding.Metadata)
}

func TestFindingMetadataMutation(t *testing.T) {
	t.Parallel()

	original := analysis.Finding{
		Metadata: map[string]string{"key": "original"},
	}

	// Shallow copy shares the map backing storage.
	copied := original
	copied.Metadata["key"] = "mutated"

	// Demonstrates that map fields share backing storage — consumers
	// must deep-copy Metadata when independent mutation is needed.
	assert.Equal(t, "mutated", original.Metadata["key"],
		"map fields share backing storage; mutation of copy affects original")
}

func TestFindingJSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := analysis.Finding{
		Type:           "security",
		Severity:       "critical",
		Title:          "Open admin port",
		Description:    "Admin port exposed to WAN",
		Recommendation: "Restrict admin access to LAN",
		Component:      "system",
		Reference:      "SANS-001",
		References:     []string{"CIS-2.1", "NIST-AC-3"},
		Tags:           []string{"admin", "exposure"},
		Metadata:       map[string]string{"port": "443", "protocol": "tcp"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var restored analysis.Finding
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, original, restored)
}
