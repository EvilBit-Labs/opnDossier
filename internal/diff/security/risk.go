// Package security provides security impact scoring for configuration changes.
package security

// RiskSummary contains aggregate security risk information for a set of changes.
type RiskSummary struct {
	Score    int        `json:"score"`
	High     int        `json:"high"`
	Medium   int        `json:"medium"`
	Low      int        `json:"low"`
	TopRisks []RiskItem `json:"top_risks,omitempty"`
}

// maxTopRisks is the maximum number of top risks to include in the summary.
const maxTopRisks = 5

// RiskItem describes a single high-priority risk.
type RiskItem struct {
	Path        string `json:"path"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
}

// HasRisks returns true if any security impacts were detected.
func (r *RiskSummary) HasRisks() bool {
	return r.High > 0 || r.Medium > 0 || r.Low > 0
}

// Severity weights for scoring.
const (
	weightHigh   = 10
	weightMedium = 5
	weightLow    = 1
)
