package diff

import (
	"context"
	"fmt"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/diff/analyzers"
	"github.com/EvilBit-Labs/opnDossier/internal/diff/security"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// OpnSenseDocument is a type alias for model.OpnSenseDocument for package convenience.
type OpnSenseDocument = model.OpnSenseDocument

// Engine orchestrates configuration comparison.
type Engine struct {
	oldConfig     *model.OpnSenseDocument
	newConfig     *model.OpnSenseDocument
	opts          Options
	logger        *logging.Logger
	analyzer      *Analyzer
	scorer        *security.Scorer
	normalizer    *analyzers.Normalizer
	orderDetector *analyzers.OrderDetector
}

// NewEngine creates a new diff engine.
func NewEngine(old, newCfg *model.OpnSenseDocument, opts Options, logger *logging.Logger) *Engine {
	return &Engine{
		oldConfig:     old,
		newConfig:     newCfg,
		opts:          opts,
		logger:        logger,
		analyzer:      NewAnalyzer(),
		scorer:        security.NewScorer(),
		normalizer:    analyzers.NewNormalizer(),
		orderDetector: analyzers.NewOrderDetector(),
	}
}

// Compare performs the comparison and returns results.
func (e *Engine) Compare(ctx context.Context) (*Result, error) {
	result := NewResult()
	result.Metadata = Metadata{
		ComparedAt:  time.Now(),
		ToolVersion: constants.Version,
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Compare each implemented section (unimplemented sections are rejected at flag validation)
	for _, section := range ImplementedSections() {
		if !e.opts.ShouldIncludeSection(section) {
			continue
		}

		changes := e.compareSection(section)
		for i := range changes {
			// Normalize displayed values if requested; skip changes where
			// normalized values are equal (cosmetic-only differences)
			if e.opts.Normalize {
				normOld := e.normalizeValue(changes[i].OldValue)
				normNew := e.normalizeValue(changes[i].NewValue)
				if changes[i].Type == ChangeModified && normOld == normNew {
					continue // Normalization removed any meaningful difference
				}
				changes[i].OldValue = normOld
				changes[i].NewValue = normNew
			}

			// Augment with pattern-based security scoring for changes without explicit impact
			if changes[i].SecurityImpact == "" {
				changes[i].SecurityImpact = e.scorer.Score(security.ChangeInput{
					Type:    changes[i].Type.String(),
					Section: changes[i].Section.String(),
					Path:    changes[i].Path,
				})
			}

			// Filter security-only if requested
			if e.opts.SecurityOnly && changes[i].SecurityImpact == "" {
				continue
			}
			result.AddChange(changes[i])
		}
	}

	// Detect firewall rule reordering if requested (after section comparison
	// so we can exclude rules that also have content changes)
	if e.opts.DetectOrder {
		e.addReorderChanges(result)
	}

	// Compute aggregate risk summary
	result.RiskSummary = e.computeRiskSummary(result)

	return result, nil
}

// computeRiskSummary calculates the aggregate risk summary from scored changes.
func (e *Engine) computeRiskSummary(result *Result) RiskSummary {
	inputs := make([]security.ChangeInput, len(result.Changes))
	for i, c := range result.Changes {
		inputs[i] = security.ChangeInput{
			Type:           c.Type.String(),
			Section:        c.Section.String(),
			Path:           c.Path,
			Description:    c.Description,
			SecurityImpact: c.SecurityImpact,
		}
	}

	return e.scorer.ScoreAll(inputs)
}

// compareSection dispatches to section-specific comparers.
func (e *Engine) compareSection(section Section) []Change {
	switch section {
	case SectionSystem:
		return e.analyzer.CompareSystem(&e.oldConfig.System, &e.newConfig.System)
	case SectionFirewall:
		return e.analyzer.CompareFirewallRules(e.oldConfig.Filter.Rule, e.newConfig.Filter.Rule)
	case SectionNAT:
		return e.analyzer.CompareNAT(&e.oldConfig.Nat, &e.newConfig.Nat)
	case SectionInterfaces:
		return e.analyzer.CompareInterfaces(&e.oldConfig.Interfaces, &e.newConfig.Interfaces)
	case SectionVLANs:
		return e.analyzer.CompareVLANs(&e.oldConfig.VLANs, &e.newConfig.VLANs)
	case SectionDHCP:
		return e.analyzer.CompareDHCP(&e.oldConfig.Dhcpd, &e.newConfig.Dhcpd)
	case SectionUsers:
		return e.analyzer.CompareUsers(e.oldConfig.System.User, e.newConfig.System.User)
	case SectionRouting:
		return e.analyzer.CompareRoutes(&e.oldConfig.StaticRoutes, &e.newConfig.StaticRoutes)
	case SectionDNS, SectionVPN, SectionCertificates:
		// These sections are defined but not yet implemented
		if e.logger != nil {
			e.logger.Warn("section comparison not yet implemented", "section", section)
		}
		return nil
	default:
		// Unknown section - this indicates a bug (section defined but not handled)
		if e.logger != nil {
			e.logger.Error("unknown section in comparison", "section", section)
		}
		return nil
	}
}

// normalizeValue applies normalization heuristics to a change value string.
func (e *Engine) normalizeValue(s string) string {
	if s == "" {
		return s
	}
	s = e.normalizer.NormalizeWhitespace(s)
	s = e.normalizer.NormalizeIP(s)
	s = e.normalizer.NormalizePort(s)
	return s
}

// addReorderChanges detects reordered firewall rules and adds them to the result,
// excluding rules that already have content changes (to avoid duplicate entries).
func (e *Engine) addReorderChanges(result *Result) {
	reorderChanges := e.detectFirewallReorders()

	// Build set of UUIDs that already have content changes
	contentChangedUUIDs := make(map[string]bool)
	for _, c := range result.Changes {
		if c.Section == SectionFirewall {
			contentChangedUUIDs[c.Path] = true
		}
	}

	for i := range reorderChanges {
		// Skip reorder if this rule also has a content change
		if contentChangedUUIDs[reorderChanges[i].Path] {
			continue
		}

		// Apply security scoring
		if reorderChanges[i].SecurityImpact == "" {
			reorderChanges[i].SecurityImpact = e.scorer.Score(security.ChangeInput{
				Type:    reorderChanges[i].Type.String(),
				Section: reorderChanges[i].Section.String(),
				Path:    reorderChanges[i].Path,
			})
		}

		// Apply security-only filtering
		if e.opts.SecurityOnly && reorderChanges[i].SecurityImpact == "" {
			continue
		}
		result.AddChange(reorderChanges[i])
	}
}

// detectFirewallReorders uses the order detector to find reordered firewall rules.
func (e *Engine) detectFirewallReorders() []Change {
	oldUUIDs := extractRuleUUIDs(e.oldConfig.Filter.Rule)
	newUUIDs := extractRuleUUIDs(e.newConfig.Filter.Rule)

	reorders := e.orderDetector.DetectReorders(oldUUIDs, newUUIDs)
	changes := make([]Change, 0, len(reorders))
	for _, r := range reorders {
		changes = append(changes, Change{
			Type:        ChangeReordered,
			Section:     SectionFirewall,
			Path:        fmt.Sprintf("filter.rule[uuid=%s]", r.ID),
			Description: fmt.Sprintf("Rule moved from position %d to %d", r.OldPosition, r.NewPosition),
		})
	}
	return changes
}

// extractRuleUUIDs returns the ordered list of UUIDs from firewall rules.
func extractRuleUUIDs(rules []schema.Rule) []string {
	uuids := make([]string, 0, len(rules))
	for _, r := range rules {
		if r.UUID != "" {
			uuids = append(uuids, r.UUID)
		}
	}
	return uuids
}
