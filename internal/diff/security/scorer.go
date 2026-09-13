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
	Type           string // "added", "removed", "modified", "reordered"
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
			if highestImpact == impactHigh {
				break // "high" is the maximum; no need to check remaining patterns
			}
		}
	}

	return highestImpact
}

// ScoredRisk is the minimal, already-scored view of a change used to build a
// RiskSummary without re-running pattern matching. Callers that have already
// populated SecurityImpact (for example the diff engine's per-change loop)
// can pass their existing values directly, avoiding a second []ChangeInput
// allocation per Compare.
type ScoredRisk struct {
	Path        string
	Description string
	Impact      string // Pre-computed impact (see Scorer.Score)
}

// SummarizeScored aggregates already-scored risks into a RiskSummary. It
// performs no pattern matching and does not rescore inputs — it simply
// tallies High/Medium/Low counts, running score, and top risks from the
// Impact field on each ScoredRisk. Compare Scorer.Score, which computes a
// single change's impact via pattern matching.
func SummarizeScored(risks []ScoredRisk) RiskSummary {
	summary := RiskSummary{}

	for i := range risks {
		accumulateRisk(&summary, risks[i].Impact, risks[i].Path, risks[i].Description)
	}

	return summary
}

// accumulateRisk updates summary in place with a single scored change. The
// TopRisks list is tier-prioritized: high-impact items are always added (up to
// maxTopRisks), and medium-impact items are only added when no high-impact
// items have been recorded yet. This holds regardless of input order: the
// first high-impact risk evicts any medium-impact entries that were added
// before it, so a run of mediums followed by a high cannot fill TopRisks and
// crowd the high out.
func accumulateRisk(summary *RiskSummary, impact, path, description string) {
	switch strings.ToLower(impact) {
	case impactHigh:
		if summary.High == 0 {
			summary.TopRisks = evictMediumRisks(summary.TopRisks)
		}
		summary.High++
		summary.Score += weightHigh
		if len(summary.TopRisks) < maxTopRisks {
			summary.TopRisks = append(summary.TopRisks, RiskItem{
				Path:        path,
				Description: description,
				Impact:      impact,
			})
		}
	case impactMedium:
		summary.Medium++
		summary.Score += weightMedium
		// Only include medium-impact items in TopRisks when no high-impact items exist.
		// This tier-based prioritization keeps the summary focused on the most critical risks.
		if summary.High == 0 && len(summary.TopRisks) < maxTopRisks {
			summary.TopRisks = append(summary.TopRisks, RiskItem{
				Path:        path,
				Description: description,
				Impact:      impact,
			})
		}
	case impactLow:
		summary.Low++
		summary.Score += weightLow
	}
}

// evictMediumRisks returns topRisks with every medium-impact entry removed,
// preserving the order and identity of everything else. Used when the first
// high-impact risk arrives, so a high never gets crowded out of TopRisks by
// mediums that were accumulated first.
func evictMediumRisks(topRisks []RiskItem) []RiskItem {
	var filtered []RiskItem
	for _, item := range topRisks {
		if !strings.EqualFold(item.Impact, impactMedium) {
			filtered = append(filtered, item)
		}
	}
	return filtered
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
