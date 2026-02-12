package diff

import (
	"context"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/diff/security"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// OpnSenseDocument is a type alias for model.OpnSenseDocument for package convenience.
type OpnSenseDocument = model.OpnSenseDocument

// Engine orchestrates configuration comparison.
type Engine struct {
	oldConfig *model.OpnSenseDocument
	newConfig *model.OpnSenseDocument
	opts      Options
	logger    *log.Logger
	analyzer  *Analyzer
	scorer    *security.Scorer
}

// NewEngine creates a new diff engine.
func NewEngine(old, newCfg *model.OpnSenseDocument, opts Options, logger *log.Logger) *Engine {
	return &Engine{
		oldConfig: old,
		newConfig: newCfg,
		opts:      opts,
		logger:    logger,
		analyzer:  NewAnalyzer(),
		scorer:    security.NewScorer(),
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

	scored := e.scorer.ScoreAll(inputs)

	rs := RiskSummary{
		Score:  scored.Score,
		High:   scored.High,
		Medium: scored.Medium,
		Low:    scored.Low,
	}
	for _, item := range scored.TopRisks {
		rs.TopRisks = append(rs.TopRisks, RiskItem{
			Path:        item.Path,
			Description: item.Description,
			Impact:      item.Impact,
		})
	}
	return rs
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
