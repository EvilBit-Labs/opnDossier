package security

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScorer_Score_PreservesAnalyzerImpact(t *testing.T) {
	scorer := NewScorer()

	change := ChangeInput{
		Type:           "added",
		Section:        "firewall",
		Path:           "filter.rule[uuid=123]",
		Description:    "Added permissive rule",
		SecurityImpact: "high",
	}

	assert.Equal(t, "high", scorer.Score(change))
}

func TestScorer_Score_PatternMatching(t *testing.T) {
	scorer := NewScorer()

	tests := []struct {
		name     string
		change   ChangeInput
		expected string
	}{
		{
			name: "firewall rule removed gets medium",
			change: ChangeInput{
				Type:    "removed",
				Section: "firewall",
				Path:    "filter.rule[uuid=abc]",
			},
			expected: "medium",
		},
		{
			name: "firewall rule added gets low",
			change: ChangeInput{
				Type:    "added",
				Section: "firewall",
				Path:    "filter.rule[uuid=abc]",
			},
			expected: "low",
		},
		{
			name: "webgui protocol change gets medium",
			change: ChangeInput{
				Type:    "modified",
				Section: "system",
				Path:    "system.webgui.protocol",
			},
			expected: "medium",
		},
		{
			name: "user added gets medium",
			change: ChangeInput{
				Type:    "added",
				Section: "users",
				Path:    "system.user[admin]",
			},
			expected: "medium",
		},
		{
			name: "user modified gets low",
			change: ChangeInput{
				Type:    "modified",
				Section: "users",
				Path:    "system.user[admin]",
			},
			expected: "low",
		},
		{
			name: "interface enable change gets medium",
			change: ChangeInput{
				Type:    "modified",
				Section: "interfaces",
				Path:    "interfaces.lan.enable",
			},
			expected: "medium",
		},
		{
			name: "hostname change has no pattern match",
			change: ChangeInput{
				Type:    "modified",
				Section: "system",
				Path:    "system.hostname",
			},
			expected: "",
		},
		{
			name: "nat mode change gets medium",
			change: ChangeInput{
				Type:    "modified",
				Section: "nat",
				Path:    "nat.outbound.mode",
			},
			expected: "medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, scorer.Score(tt.change))
		})
	}
}

func TestScorer_ScoreAll(t *testing.T) {
	scorer := NewScorer()

	changes := []ChangeInput{
		{
			Type:           "added",
			Section:        "firewall",
			Path:           "filter.rule[uuid=abc]",
			Description:    "Added permissive rule",
			SecurityImpact: "high",
		},
		{
			Type:        "removed",
			Section:     "firewall",
			Path:        "filter.rule[uuid=def]",
			Description: "Removed rule",
		},
		{
			Type:        "modified",
			Section:     "system",
			Path:        "system.hostname",
			Description: "Hostname changed",
		},
	}

	summary := scorer.ScoreAll(changes)

	assert.Equal(t, 1, summary.High)
	assert.Equal(t, 1, summary.Medium)
	assert.Equal(t, 0, summary.Low)
	assert.True(t, summary.HasRisks())
	assert.Equal(t, weightHigh+weightMedium, summary.Score)
	// TopRisks uses tier-based prioritization: only high-impact items are included
	// when high-impact changes exist (medium items are excluded).
	require.Len(t, summary.TopRisks, 1)
	assert.Equal(t, "high", summary.TopRisks[0].Impact)
}

func TestSummarizeScored(t *testing.T) {
	t.Parallel()

	// SummarizeScored mirrors ScoreAll but skips pattern matching — callers
	// supply the already-computed Impact. Arrange a mix of high/medium/low
	// items plus an unscored one and assert tier-based TopRisks prioritization.
	risks := []ScoredRisk{
		{Path: "filter.rule[uuid=abc]", Description: "Added permissive rule", Impact: "high"},
		{Path: "filter.rule[uuid=def]", Description: "Removed rule", Impact: "medium"},
		{Path: "system.hostname", Description: "Hostname changed", Impact: ""},
		{Path: "filter.rule[uuid=ghi]", Description: "Low-impact change", Impact: "low"},
	}

	summary := SummarizeScored(risks)

	assert.Equal(t, 1, summary.High)
	assert.Equal(t, 1, summary.Medium)
	assert.Equal(t, 1, summary.Low)
	assert.True(t, summary.HasRisks())
	assert.Equal(t, weightHigh+weightMedium+weightLow, summary.Score)
	// TopRisks uses tier-based prioritization: the high-impact entry squeezes
	// out the medium entry once a high is recorded.
	require.Len(t, summary.TopRisks, 1)
	assert.Equal(t, "high", summary.TopRisks[0].Impact)
	assert.Equal(t, "filter.rule[uuid=abc]", summary.TopRisks[0].Path)
}

func TestSummarizeScored_MediumOnly(t *testing.T) {
	t.Parallel()

	// When there are no high-impact items, medium-impact items populate TopRisks
	// (up to maxTopRisks). This mirrors the tier-based branch in accumulateRisk.
	risks := []ScoredRisk{
		{Path: "a", Description: "d-a", Impact: "medium"},
		{Path: "b", Description: "d-b", Impact: "medium"},
	}

	summary := SummarizeScored(risks)

	assert.Equal(t, 0, summary.High)
	assert.Equal(t, 2, summary.Medium)
	require.Len(t, summary.TopRisks, 2)
}

func TestSummarizeScored_Empty(t *testing.T) {
	t.Parallel()

	summary := SummarizeScored(nil)

	assert.False(t, summary.HasRisks())
	assert.Equal(t, 0, summary.Score)
	assert.Empty(t, summary.TopRisks)
}

func TestScorer_ScoreAll_NoRisks(t *testing.T) {
	scorer := NewScorer()

	changes := []ChangeInput{
		{
			Type:        "modified",
			Section:     "system",
			Path:        "system.hostname",
			Description: "Hostname changed",
		},
	}

	summary := scorer.ScoreAll(changes)

	assert.False(t, summary.HasRisks())
	assert.Equal(t, 0, summary.Score)
	assert.Empty(t, summary.TopRisks)
}

func TestNewScorerWithPatterns(t *testing.T) {
	custom := []Pattern{
		{
			Name:      "custom-pattern",
			Section:   "system",
			PathRegex: regexp.MustCompile(`system\.hostname`),
			Impact:    "high",
		},
	}

	scorer := NewScorerWithPatterns(custom)

	change := ChangeInput{
		Type:    "modified",
		Section: "system",
		Path:    "system.hostname",
	}

	assert.Equal(t, "high", scorer.Score(change))
}

func TestHigherImpact(t *testing.T) {
	tests := []struct {
		name           string
		a, b, expected string
	}{
		{"both empty", "", "", ""},
		{"low vs empty", "low", "", "low"},
		{"empty vs high", "", "high", "high"},
		{"low vs medium", "low", "medium", "medium"},
		{"high vs low", "high", "low", "high"},
		{"medium vs high", "medium", "high", "high"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, higherImpact(tt.a, tt.b))
		})
	}
}

func TestRiskSummary_HasRisks(t *testing.T) {
	assert.False(t, (&RiskSummary{}).HasRisks())
	assert.True(t, (&RiskSummary{High: 1}).HasRisks())
	assert.True(t, (&RiskSummary{Medium: 1}).HasRisks())
	assert.True(t, (&RiskSummary{Low: 1}).HasRisks())

	// Nil receiver should not panic
	var nilSummary *RiskSummary
	assert.False(t, nilSummary.HasRisks())
}
