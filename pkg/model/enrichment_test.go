package model_test

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

func TestComplianceResults_HasData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		results  common.ComplianceResults
		expected bool
	}{
		{
			name:     "zero value has no data",
			results:  common.ComplianceResults{},
			expected: false,
		},
		{
			name:     "mode set",
			results:  common.ComplianceResults{Mode: "blue"},
			expected: true,
		},
		{
			name: "findings present",
			results: common.ComplianceResults{
				Findings: []common.ComplianceFinding{{Title: "test"}},
			},
			expected: true,
		},
		{
			name: "plugin results present",
			results: common.ComplianceResults{
				PluginResults: map[string]common.PluginComplianceResult{
					"plugin": {},
				},
			},
			expected: true,
		},
		{
			name: "summary present",
			results: common.ComplianceResults{
				Summary: &common.ComplianceResultSummary{TotalFindings: 1},
			},
			expected: true,
		},
		{
			name: "metadata present",
			results: common.ComplianceResults{
				Metadata: map[string]any{"key": "value"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.results.HasData()
			if got != tt.expected {
				t.Errorf("ComplianceResults.HasData() = %v, want %v", got, tt.expected)
			}
		})
	}
}
