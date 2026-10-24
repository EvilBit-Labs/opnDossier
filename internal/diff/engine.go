package diff

import (
	"context"
	"fmt"
	"slices"
	"strings"
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
			// Normalize displayed values if requested, and skip a change that
			// formattingOnly reports as differing only in formatting.
			if e.opts.Normalize {
				normOld := e.normalizeValue(changes[i].OldValue)
				normNew := e.normalizeValue(changes[i].NewValue)
				if formattingOnly(changes[i], normOld, normNew) {
					continue
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

// formattingOnly reports whether normalization removed the only difference a
// modified entry had, given its normalized values.
//
// The values must be all that was compared. A summarized entry is never
// formatting only: its values leave fields out, so equal text after
// normalization says nothing about them. Values that were already equal are
// not either, since the entry was reported for something they do not show.
func formattingOnly(c Change, normOld, normNew string) bool {
	return c.Type == ChangeModified && !c.summarized &&
		c.OldValue != c.NewValue && normOld == normNew
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
		// Skip reorder if this rule also has a content change. The copies of
		// a rule share the path of a content change, so a change to one of
		// them skips the moves of all of them.
		if contentChangedUUIDs[withoutCopy(reorderChanges[i].Path)] {
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
	oldIDs := ruleIdentities(e.oldConfig.FirewallRules)
	newIDs := pairedRuleIdentities(e.oldConfig.FirewallRules, e.newConfig.FirewallRules)

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

// ruleIdentities returns the ordered identifiers of the rules that have one.
// Rules that share one, as a rule and the copy OPNsense's migration assistant
// makes of it do, are told apart by a count in list order: the second is
// "<id>,copy=1". One identifier for both would keep only the last place.
//
// This previously read UUIDs only, so it returned an empty list for any config
// whose rules carry no <uuid> -- which is every pfSense config and every older
// OPNsense one. DetectReorders then had nothing to compare and --detect-order
// was a documented flag that silently did nothing for most real inputs.
func ruleIdentities(rules []common.FirewallRule) []string {
	ids := make([]string, len(rules))

	for id, positions := range groupByIdentity(rules) {
		for n, i := range positions {
			ids[i] = copyIdentity(id, n)
		}
	}

	return slices.DeleteFunc(ids, unidentified)
}

// pairedRuleIdentities returns the identifiers of the rules of newRules as
// ruleIdentities does, except that a rule sharing its identifier takes the count
// of the rule of old that sameUUIDPairer pairs it with, the pairing
// CompareFirewallRules gives rules that share a uuid. A copy therefore keeps its
// identifier when the copies swap places, where a count in list order would hand
// each copy's name to the other. A rule without a partner counts on from the old
// side's copies.
func pairedRuleIdentities(old, newRules []common.FirewallRule) []string {
	oldGroups := groupByIdentity(old)
	ids := make([]string, len(newRules))

	for id, positions := range groupByIdentity(newRules) {
		oldCopies := rulesAt(old, oldGroups[id])
		partner := make([]int, len(positions))

		res := sameUUIDPairer.pair(oldCopies, rulesAt(newRules, positions), func(oi, ni int) { partner[ni] = oi })

		next := len(oldCopies)
		for n, i := range positions {
			if res.newPaired[n] {
				ids[i] = copyIdentity(id, partner[n])
			} else {
				ids[i] = copyIdentity(id, next)
				next++
			}
		}
	}

	return slices.DeleteFunc(ids, unidentified)
}

// unidentified reports whether a slot of ruleIdentities holds no identifier.
func unidentified(id string) bool {
	return id == ""
}

// groupByIdentity returns the positions of the rules that have an identifier,
// by identifier, in list order.
func groupByIdentity(rules []common.FirewallRule) map[string][]int {
	groups := make(map[string][]int, len(rules))

	for i, rule := range rules {
		if id, ok := ruleIdentity(rule); ok {
			groups[id] = append(groups[id], i)
		}
	}

	return groups
}

// rulesAt returns the rules at the given positions.
func rulesAt(rules []common.FirewallRule, positions []int) []common.FirewallRule {
	picked := make([]common.FirewallRule, 0, len(positions))
	for _, i := range positions {
		picked = append(picked, rules[i])
	}

	return picked
}

// copyIdentity returns the identifier of the nth rule that shares id.
func copyIdentity(id string, n int) string {
	if n == 0 {
		return id
	}

	return fmt.Sprintf("%s%s%d", id, copySuffix, n)
}

// copySuffix marks the count ruleIdentities adds to a shared identifier.
const copySuffix = ",copy="

// withoutCopy returns the path of a reordered rule without the count that tells
// it from the other rules sharing its identifier.
func withoutCopy(path string) string {
	if i := strings.LastIndex(path, copySuffix); i >= 0 {
		return path[:i] + "]"
	}

	return path
}
