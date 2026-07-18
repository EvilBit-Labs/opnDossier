package analysis

import "slices"

// Confidence represents how confident the shared detection engine is that an
// Observation reflects a real, actionable condition. Confidence never gates
// whether an observation is surfaced — every match is reported regardless of
// its confidence label; confidence is presentation metadata only.
type Confidence string

// Confidence level constants define the three-level confidence scale shared
// by observations, blue hygiene findings, and red findings.
const (
	// ConfidenceHigh indicates a deterministic, low-false-positive detection.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium indicates a detection with plausible false positives.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow indicates a heuristic detection with a higher false-positive rate.
	ConfidenceLow Confidence = "low"
)

// ValidConfidences returns a fresh copy of all valid confidence values.
// Returns a new slice each call to prevent callers from mutating shared state.
func ValidConfidences() []Confidence {
	return []Confidence{ConfidenceHigh, ConfidenceMedium, ConfidenceLow}
}

// String returns the string representation of the confidence level.
func (c Confidence) String() string {
	return string(c)
}

// IsValidConfidence checks whether the given confidence is a recognized value.
func IsValidConfidence(c Confidence) bool {
	return slices.Contains(ValidConfidences(), c)
}

// Observation is a neutral, mode-agnostic detection produced by the shared
// detection engine (ScanObservations). Blue and red audit modes are
// presentation lenses over the same observations, so detection logic lives
// here exactly once and the two modes cannot disagree about the underlying
// facts. See docs/plans/2026-07-17-001-feat-audit-blue-red-analysis-plan.md.
type Observation struct {
	// Severity is the shared severity scale value (critical..info), aligned
	// with the compliance-plugin severity vocabulary.
	Severity Severity `json:"severity"`
	// Confidence labels how certain the detection is; never used to drop an
	// observation.
	Confidence Confidence `json:"confidence"`
	// Reachability tags where this observation is reachable from: WAN, LAN,
	// or local only.
	Reachability Reachability `json:"reachability"`
	// Component identifies the originating configuration element (e.g.
	// "filter.rule[3]", "system.webgui.protocol").
	Component string `json:"component"`
	// Evidence carries a human-readable pointer to the specific config value
	// that triggered the observation.
	Evidence string `json:"evidence,omitempty"`
	// Title is a brief description of the observation.
	Title string `json:"title"`
	// Description provides detailed information about the observation.
	Description string `json:"description"`
	// Recommendation suggests how to address the observation.
	Recommendation string `json:"recommendation"`
}

// ToFinding maps the observation into the canonical analysis.Finding shape
// consumed by blue-mode hygiene rendering. analysis.Finding has no dedicated
// confidence/reachability/evidence fields, so those three axes are carried
// in Metadata rather than dropped.
func (o Observation) ToFinding() Finding {
	return Finding{
		Type:           "hygiene",
		Severity:       string(o.Severity),
		Title:          o.Title,
		Description:    o.Description,
		Recommendation: o.Recommendation,
		Component:      o.Component,
		Metadata: map[string]string{
			"confidence":   string(o.Confidence),
			"reachability": string(o.Reachability),
			"evidence":     o.Evidence,
		},
	}
}
