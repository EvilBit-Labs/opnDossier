package security

import (
	"strings"
)

// Security impact level constants.
const (
	impactHigh   = "high"
	impactMedium = "medium"
	impactLow    = "low"
)

// Impact ordering constants.
const (
	impactOrdHigh   = 3
	impactOrdMedium = 2
	impactOrdLow    = 1
)

// ChangeInput is the minimal change information needed for security scoring.
// This avoids an import cycle with the parent diff package.
type ChangeInput struct {
	Type           string // "added", "removed", "modified"
	Section        string // "firewall", "system", "nat", etc.
	Path           string // Configuration path
	Description    string
	SecurityImpact string // Existing impact from analyzer (preserved if non-empty)
}

// Scorer evaluates security impact of configuration changes.
type Scorer struct {
	patterns []Pattern
}

// NewScorer creates a Scorer with the default security patterns.
func NewScorer() *Scorer {
	return &Scorer{
		patterns: DefaultPatterns(),
	}
}

// NewScorerWithPatterns creates a Scorer with custom patterns.
func NewScorerWithPatterns(patterns []Pattern) *Scorer {
	return &Scorer{
		patterns: patterns,
	}
}

// Score evaluates a single change and returns the highest applicable security impact.
// If the change already has a SecurityImpact set (from analyzer domain logic), it is preserved.
// Otherwise, the scorer applies pattern-based matching.
func (s *Scorer) Score(change ChangeInput) string {
	// Preserve analyzer-assigned impact — it has domain-specific context
	if change.SecurityImpact != "" {
		return change.SecurityImpact
	}

	highestImpact := ""
	for _, p := range s.patterns {
		if s.matches(p, change) {
			highestImpact = higherImpact(highestImpact, p.Impact)
		}
	}

	return highestImpact
}

// ScoreAll computes an aggregate risk summary for a set of changes.
func (s *Scorer) ScoreAll(changes []ChangeInput) RiskSummary {
	summary := RiskSummary{}

	for _, change := range changes {
		impact := s.Score(change)
		switch strings.ToLower(impact) {
		case impactHigh:
			summary.High++
			summary.Score += weightHigh
			if len(summary.TopRisks) < maxTopRisks {
				summary.TopRisks = append(summary.TopRisks, RiskItem{
					Path:        change.Path,
					Description: change.Description,
					Impact:      impact,
				})
			}
		case impactMedium:
			summary.Medium++
			summary.Score += weightMedium
			if summary.High == 0 && len(summary.TopRisks) < maxTopRisks {
				summary.TopRisks = append(summary.TopRisks, RiskItem{
					Path:        change.Path,
					Description: change.Description,
					Impact:      impact,
				})
			}
		case impactLow:
			summary.Low++
			summary.Score += weightLow
		}
	}

	return summary
}

// matches checks if a pattern applies to a change.
func (s *Scorer) matches(p Pattern, change ChangeInput) bool {
	// Match section
	if p.Section != "" && !strings.EqualFold(p.Section, change.Section) {
		return false
	}

	// Match path regex
	if p.PathRegex != nil && !p.PathRegex.MatchString(change.Path) {
		return false
	}

	// Match change type
	if p.ChangeType != "" && !strings.EqualFold(p.ChangeType, change.Type) {
		return false
	}

	return true
}

// higherImpact returns the higher of two impact levels.
func higherImpact(a, b string) string {
	return impactLevel(max(impactOrd(a), impactOrd(b)))
}

// impactOrd returns a numeric ordering for impact levels.
func impactOrd(impact string) int {
	switch strings.ToLower(impact) {
	case impactHigh:
		return impactOrdHigh
	case impactMedium:
		return impactOrdMedium
	case impactLow:
		return impactOrdLow
	default:
		return 0
	}
}

// impactLevel converts a numeric ordering back to an impact string.
func impactLevel(ord int) string {
	switch ord {
	case impactOrdHigh:
		return impactHigh
	case impactOrdMedium:
		return impactMedium
	case impactOrdLow:
		return impactLow
	default:
		return ""
	}
}
