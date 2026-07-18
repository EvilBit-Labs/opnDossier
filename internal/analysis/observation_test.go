package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/stretchr/testify/assert"
)

// TestObservation_CarriesAllFourAxes covers U2's requirement that an
// Observation carries severity, confidence, evidence, and reachability
// (R1, R6).
func TestObservation_CarriesAllFourAxes(t *testing.T) {
	t.Parallel()

	obs := analysis.Observation{
		Severity:       analysis.SeverityHigh,
		Confidence:     analysis.ConfidenceMedium,
		Reachability:   analysis.WANReachable,
		Component:      "filter.rule[3]",
		Evidence:       "rule allows any source on wan",
		Title:          "Overly Permissive WAN Rule",
		Description:    "Rule 3 allows any source to pass traffic on WAN interface",
		Recommendation: "Restrict source networks",
	}

	assert.Equal(t, analysis.SeverityHigh, obs.Severity)
	assert.Equal(t, analysis.ConfidenceMedium, obs.Confidence)
	assert.Equal(t, analysis.WANReachable, obs.Reachability)
	assert.Equal(t, "filter.rule[3]", obs.Component)
	assert.Equal(t, "rule allows any source on wan", obs.Evidence)
	assert.Equal(t, "Overly Permissive WAN Rule", obs.Title)
	assert.Equal(t, "Rule 3 allows any source to pass traffic on WAN interface", obs.Description)
	assert.Equal(t, "Restrict source networks", obs.Recommendation)
}

// TestConfidence_RoundTrips covers the confidence label round-trip and
// vocabulary requirement (R6).
func TestConfidence_RoundTrips(t *testing.T) {
	t.Parallel()

	for _, c := range analysis.ValidConfidences() {
		assert.True(t, analysis.IsValidConfidence(c))
		assert.Equal(t, string(c), c.String())
	}

	assert.False(t, analysis.IsValidConfidence(analysis.Confidence("bogus")))
}

// TestValidSeverities_MatchSharedVocabulary pins that Observation reuses the
// existing analysis.Severity vocabulary (KTD2) rather than introducing a
// second severity type.
func TestValidSeverities_MatchSharedVocabulary(t *testing.T) {
	t.Parallel()

	for _, s := range analysis.ValidSeverities() {
		obs := analysis.Observation{Severity: s}
		assert.True(t, analysis.IsValidSeverity(obs.Severity))
	}
}

// TestObservation_ToFinding_PreservesSeverityComponentEvidence covers U2's
// mapper test scenario: ToFinding preserves severity/component/evidence.
func TestObservation_ToFinding_PreservesSeverityComponentEvidence(t *testing.T) {
	t.Parallel()

	obs := analysis.Observation{
		Severity:       analysis.SeverityCritical,
		Confidence:     analysis.ConfidenceHigh,
		Reachability:   analysis.LANOnly,
		Component:      "system.webgui.protocol",
		Evidence:       "protocol=http",
		Title:          "Insecure Web GUI Protocol",
		Description:    "Web GUI is configured to use HTTP instead of HTTPS",
		Recommendation: "Change web GUI protocol to HTTPS",
	}

	finding := obs.ToFinding()

	assert.Equal(t, string(analysis.SeverityCritical), finding.Severity)
	assert.Equal(t, "system.webgui.protocol", finding.Component)
	assert.Equal(t, obs.Title, finding.Title)
	assert.Equal(t, obs.Description, finding.Description)
	assert.Equal(t, obs.Recommendation, finding.Recommendation)
	assert.Equal(t, "protocol=http", finding.Metadata["evidence"])
	assert.Equal(t, string(analysis.ConfidenceHigh), finding.Metadata["confidence"])
	assert.Equal(t, string(analysis.LANOnly), finding.Metadata["reachability"])
}
