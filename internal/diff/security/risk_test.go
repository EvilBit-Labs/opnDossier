package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// HasRisks returns true if any security impacts were detected.
//
// Moved here from risk.go: no production caller reaches it (production reads
// RiskSummary.High/Medium/Low directly, or serializes the struct as-is for
// --format json/yaml), but it is a convenience predicate this package's own
// tests lean on heavily (TestSummarizeScored and friends). Declaring it in a
// _test.go file keeps it out of the shipped binary while still attaching it
// to RiskSummary for every test in this package -- the same treatment
// internal/sanitizer.ValidModes and internal/converter's test_helpers.go
// (see docs/development/standards.md, "Place shared helpers in a _test.go
// file when the helper's only callers are tests in its own package") get for
// the identical shape of gap.
func (r *RiskSummary) HasRisks() bool {
	if r == nil {
		return false
	}
	return r.High > 0 || r.Medium > 0 || r.Low > 0
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
