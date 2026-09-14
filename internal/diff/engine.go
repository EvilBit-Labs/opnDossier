package diff

import (
	"context"
	"fmt"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/diff/analyzers"
	"github.com/EvilBit-Labs/opnDossier/internal/diff/security"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// Engine orchestrates configuration comparison.
type Engine struct {
	oldConfig     *common.CommonDevice
	newConfig     *common.CommonDevice
	opts          Options
	logger        *logging.Logger
	analyzer      *Analyzer
	scorer        *security.Scorer
	normalizer    *analyzers.Normalizer
	orderDetector *analyzers.OrderDetector
}

// NewEngine creates a new diff engine.
func NewEngine(old, newCfg *common.CommonDevice, opts Options, logger *logging.Logger) *Engine {
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

	// Populate device type metadata
	result.DeviceType.Old = string(e.oldConfig.DeviceType)
	result.DeviceType.New = string(e.newConfig.DeviceType)

	return result, nil
}

// computeRiskSummary calculates the aggregate risk summary from scored changes.
//
// Each Change in result.Changes already has SecurityImpact populated by the
// per-change loop in Compare (and by addReorderChanges). We aggregate those
// existing values directly via security.SummarizeScored instead of rebuilding
// a []ChangeInput and re-running pattern matching through Scorer.Score per
// change — this eliminates a second O(n) allocation on large diffs (PERF-M6).
func (e *Engine) computeRiskSummary(result *Result) RiskSummary {
	risks := make([]security.ScoredRisk, len(result.Changes))
	for i, c := range result.Changes {
		risks[i] = security.ScoredRisk{
			Path:        c.Path,
			Description: c.Description,
			Impact:      c.SecurityImpact,
		}
	}

	return security.SummarizeScored(risks)
}

// compareSection dispatches to section-specific comparers.
func (e *Engine) compareSection(section Section) []Change {
	switch section {
	case SectionSystem:
		return e.analyzer.CompareSystem(&e.oldConfig.System, &e.newConfig.System)
	case SectionFirewall:
		return e.analyzer.CompareFirewallRules(e.oldConfig.FirewallRules, e.newConfig.FirewallRules)
	case SectionNAT:
		return e.analyzer.CompareNAT(e.oldConfig.NAT, e.newConfig.NAT)
	case SectionInterfaces:
		return e.analyzer.CompareInterfaces(e.oldConfig.Interfaces, e.newConfig.Interfaces)
	case SectionVLANs:
		return e.analyzer.CompareVLANs(e.oldConfig.VLANs, e.newConfig.VLANs)
	case SectionDHCP:
		return e.analyzer.CompareDHCP(e.oldConfig.DHCP, e.newConfig.DHCP)
	case SectionUsers:
		return e.analyzer.CompareUsers(e.oldConfig.Users, e.newConfig.Users)
	case SectionRouting:
		return e.analyzer.CompareRoutes(e.oldConfig.Routing, e.newConfig.Routing)
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
	contentChangedUUIDs := make(map[string]bool, len(result.Changes))
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
	oldIDs := extractRuleIdentities(e.oldConfig.FirewallRules)
	newIDs := extractRuleIdentities(e.newConfig.FirewallRules)

	reorders := e.orderDetector.DetectReorders(oldIDs, newIDs)
	changes := make([]Change, 0, len(reorders))
	for _, r := range reorders {
		changes = append(changes, Change{
			Type:        ChangeReordered,
			Section:     SectionFirewall,
			Path:        "filter.rule[" + r.ID + "]",
			Description: fmt.Sprintf("Rule moved from position %d to %d", r.OldPosition, r.NewPosition),
		})
	}
	return changes
}

// ruleIdentity returns the stable identifier a rule can be tracked by across
// two configs: its UUID when it has one, otherwise its pfSense <tracker>. The
// second return is false when the rule carries neither, in which case it cannot
// participate in order detection -- a rule with no identity is
// indistinguishable from its peers, so "it moved" is not a claim that can be
// made about it.
func ruleIdentity(rule common.FirewallRule) (string, bool) {
	if rule.UUID != "" {
		return "uuid=" + rule.UUID, true
	}

	if rule.Tracker != "" {
		return "tracker=" + rule.Tracker, true
	}

	return "", false
}

// extractRuleIdentities returns the ordered identifiers of the rules that have
// one.
//
// This previously read UUIDs only, so it returned an empty list for any config
// whose rules carry no <uuid> -- which is every pfSense config and every older
// OPNsense one. DetectReorders then had nothing to compare and --detect-order
// was a documented flag that silently did nothing for most real inputs.
func extractRuleIdentities(rules []common.FirewallRule) []string {
	ids := make([]string, 0, len(rules))

	for _, r := range rules {
		if id, ok := ruleIdentity(r); ok {
			ids = append(ids, id)
		}
	}

	return ids
}
