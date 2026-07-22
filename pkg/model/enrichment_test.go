package model_test

import (
	"encoding/json"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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

// TestShadowedRuleFinding_WireKeys is a JSON/YAML marshal round-trip
// regression guarding the wire shape of ShadowedRuleFinding — catches a tag
// typo or an accidental omitempty reintroduction on RuleIndex/
// ShadowedByIndex (P3: index 0, the first rule, must never be dropped by
// omitempty since it is indistinguishable from "unset").
func TestShadowedRuleFinding_WireKeys(t *testing.T) {
	t.Parallel()

	analysis := common.Analysis{
		ShadowedRules: []common.ShadowedRuleFinding{
			{
				Kind:            common.ShadowKindFull,
				ImpactClass:     common.ImpactClassSecurity,
				Severity:        common.SeverityCritical,
				Confidence:      common.ConfidenceHigh,
				RuleIndex:       0,
				ShadowedByIndex: 0,
				Interface:       "wan",
				Direction:       "in",
			},
		},
	}

	t.Run("json", func(t *testing.T) {
		t.Parallel()

		data, err := json.Marshal(analysis)
		require.NoError(t, err)

		var doc map[string]any
		require.NoError(t, json.Unmarshal(data, &doc))

		shadowed, ok := doc["shadowedRules"].([]any)
		require.True(t, ok, "expected top-level shadowedRules key")
		require.Len(t, shadowed, 1)

		finding, ok := shadowed[0].(map[string]any)
		require.True(t, ok)

		for _, key := range []string{
			"kind", "impactClass", "severity", "confidence",
			"ruleIndex", "shadowedByIndex", "interface", "direction",
		} {
			assert.Contains(t, finding, key, "missing wire key %q", key)
		}

		// The P3 regression: index 0 must survive, not be omitted.
		assert.InDelta(t, float64(0), finding["ruleIndex"], 0, "ruleIndex 0 must not be omitted")
		assert.InDelta(t, float64(0), finding["shadowedByIndex"], 0, "shadowedByIndex 0 must not be omitted")
	})

	t.Run("yaml", func(t *testing.T) {
		t.Parallel()

		data, err := yaml.Marshal(analysis)
		require.NoError(t, err)

		var doc map[string]any
		require.NoError(t, yaml.Unmarshal(data, &doc))

		shadowed, ok := doc["shadowedRules"].([]any)
		require.True(t, ok, "expected top-level shadowedRules key")
		require.Len(t, shadowed, 1)

		finding, ok := shadowed[0].(map[string]any)
		require.True(t, ok)

		for _, key := range []string{
			"kind", "impactClass", "severity", "confidence",
			"ruleIndex", "shadowedByIndex", "interface", "direction",
		} {
			assert.Contains(t, finding, key, "missing wire key %q", key)
		}

		assert.Equal(t, 0, finding["ruleIndex"], "ruleIndex 0 must not be omitted")
		assert.Equal(t, 0, finding["shadowedByIndex"], "shadowedByIndex 0 must not be omitted")
	})
}
