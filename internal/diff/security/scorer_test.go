package security

import (
	"strconv"
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

func TestSummarizeScored(t *testing.T) {
	t.Parallel()

	// SummarizeScored aggregates pre-scored risks without pattern matching — callers
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

func TestSummarizeScored_MediumsFirstThenHigh(t *testing.T) {
	t.Parallel()

	// Tier-prioritization must hold regardless of input order: mediums that
	// arrive before the first high must be evicted from TopRisks once that
	// high is recorded, not left in place crowding it out.
	risks := []ScoredRisk{
		{Path: "a", Description: "d-a", Impact: "medium"},
		{Path: "b", Description: "d-b", Impact: "medium"},
		{Path: "c", Description: "d-c", Impact: "high"},
	}

	summary := SummarizeScored(risks)

	assert.Equal(t, 1, summary.High)
	assert.Equal(t, 2, summary.Medium)
	require.Len(t, summary.TopRisks, 1)
	assert.Equal(t, "high", summary.TopRisks[0].Impact)
	assert.Equal(t, "c", summary.TopRisks[0].Path)
}

func TestSummarizeScored_MediumsFillCapThenHigh(t *testing.T) {
	t.Parallel()

	// Enough mediums to fill maxTopRisks arrive first; the high that follows
	// must still appear in TopRisks rather than being dropped because the cap
	// was already reached by mediums.
	risks := make([]ScoredRisk, 0, maxTopRisks+1)
	for i := range maxTopRisks {
		risks = append(risks, ScoredRisk{
			Path:        "medium-" + strconv.Itoa(i),
			Description: "medium change",
			Impact:      "medium",
		})
	}
	risks = append(risks, ScoredRisk{Path: "the-high", Description: "high change", Impact: "high"})

	summary := SummarizeScored(risks)

	assert.Equal(t, 1, summary.High)
	assert.Equal(t, maxTopRisks, summary.Medium)
	require.Len(t, summary.TopRisks, 1)
	assert.Equal(t, "high", summary.TopRisks[0].Impact)
	assert.Equal(t, "the-high", summary.TopRisks[0].Path)
}

func TestSummarizeScored_Empty(t *testing.T) {
	t.Parallel()

	summary := SummarizeScored(nil)

	assert.False(t, summary.HasRisks())
	assert.Equal(t, 0, summary.Score)
	assert.Empty(t, summary.TopRisks)
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
