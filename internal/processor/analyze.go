package processor

import (
	"context"
	"fmt"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// analyze performs comprehensive analysis of the device configuration based on enabled options.
func (p *CoreProcessor) analyze(_ context.Context, cfg *common.CommonDevice, config *Config, report *Report) {
	// Dead rule detection
	if config.EnableDeadRuleCheck {
		p.analyzeDeadRules(cfg, report)
	}

	// Unused interfaces analysis
	if config.EnableSecurityAnalysis || config.EnableComplianceCheck {
		p.analyzeUnusedInterfaces(cfg, report)
	}

	// Consistency checks
	if config.EnableComplianceCheck {
		p.analyzeConsistency(cfg, report)
	}

	// Security analysis
	if config.EnableSecurityAnalysis {
		p.analyzeSecurityIssues(cfg, report)
	}

	// Performance analysis
	if config.EnablePerformanceAnalysis {
		p.analyzePerformanceIssues(cfg, report)
	}
}

// analyzeDeadRules detects firewall rules that are never hit or are effectively dead.
// It delegates to analysis.DetectDeadRules for block-all and duplicate detection,
// then checks for processor-specific overly broad pass rules.
func (p *CoreProcessor) analyzeDeadRules(cfg *common.CommonDevice, report *Report) {
	deadRules := analysis.DetectDeadRules(cfg)
	for _, f := range deadRules {
		switch f.Kind {
		case common.DeadRuleKindDuplicate:
			report.AddFinding(SeverityLow, Finding{
				Type:           "duplicate-rule",
				Title:          "Duplicate Firewall Rule",
				Description:    f.Description,
				Component:      fmt.Sprintf("filter.rule[%d]", f.RuleIndex),
				Recommendation: f.Recommendation,
			})
		default:
			report.AddFinding(SeverityMedium, Finding{
				Type:           "dead-rule",
				Title:          "Unreachable Rules After Block All",
				Description:    f.Description,
				Component:      fmt.Sprintf("filter.rule[%d]", f.RuleIndex),
				Recommendation: f.Recommendation,
			})
		}
	}

	// Processor-specific check: overly broad pass rules without description
	checkBroadPassRules(cfg, report)
}

// checkBroadPassRules detects pass rules with any source and no description,
// which may indicate unintentional overly permissive rules. This is a
// processor-specific check not included in the shared analysis package.
func checkBroadPassRules(cfg *common.CommonDevice, report *Report) {
	for i, rule := range cfg.FirewallRules {
		if rule.Type == common.RuleTypePass && rule.Source.Address == constants.NetworkAny &&
			rule.Description == "" {
			for _, iface := range rule.Interfaces {
				report.AddFinding(SeverityHigh, Finding{
					Type:  constants.FindingTypeSecurity,
					Title: "Overly Broad Pass Rule",
					Description: fmt.Sprintf(
						"Rule at position %d on interface %s allows all traffic without description",
						i+1,
						iface,
					),
					Component:      fmt.Sprintf("filter.rule[%d]", i),
					Recommendation: "Add description and consider restricting source or destination",
				})
			}
		}
	}
}

// analyzeUnusedInterfaces detects interfaces that are defined but not used in rules or services.
func (p *CoreProcessor) analyzeUnusedInterfaces(cfg *common.CommonDevice, report *Report) {
	unused := analysis.DetectUnusedInterfaces(cfg)
	for _, f := range unused {
		report.AddFinding(SeverityLow, Finding{
			Type:           "unused-interface",
			Title:          "Unused Network Interface",
			Description:    f.Description,
			Component:      "interfaces." + f.InterfaceName,
			Recommendation: f.Recommendation,
		})
	}
}

// analyzeConsistency performs consistency checks across the configuration.
func (p *CoreProcessor) analyzeConsistency(cfg *common.CommonDevice, report *Report) {
	issues := analysis.DetectConsistency(cfg)
	for _, f := range issues {
		report.AddFinding(mapSeverity(f.Severity), Finding{
			Type:           "consistency",
			Title:          f.Issue,
			Description:    f.Description,
			Component:      f.Component,
			Recommendation: f.Recommendation,
		})
	}
}

// analyzeSecurityIssues performs security-focused analysis.
func (p *CoreProcessor) analyzeSecurityIssues(cfg *common.CommonDevice, report *Report) {
	issues := analysis.DetectSecurityIssues(cfg)

	// Reference strings provide additional context for processor findings.
	referenceMap := map[string]string{
		"system.webgui.protocol": "HTTPS provides encryption for administrative access",
		"snmpd.rocommunity":      "Default community strings are well-known and pose security risks",
	}

	for _, f := range issues {
		ref := referenceMap[f.Component]
		if ref == "" && strings.HasPrefix(f.Component, "filter.rule[") {
			ref = "WAN interfaces should have restrictive inbound rules"
		}

		report.AddFinding(mapSeverity(f.Severity), Finding{
			Type:           constants.FindingTypeSecurity,
			Title:          f.Issue,
			Description:    f.Description,
			Component:      f.Component,
			Recommendation: f.Recommendation,
			Reference:      ref,
		})
	}
}

// analyzePerformanceIssues performs performance-focused analysis.
func (p *CoreProcessor) analyzePerformanceIssues(cfg *common.CommonDevice, report *Report) {
	issues := analysis.DetectPerformanceIssues(cfg)

	// Reference strings provide additional context for processor findings.
	referenceMap := map[string]string{
		"system.disablechecksumoffloading":     "Hardware offloading can improve network performance",
		"system.disablesegmentationoffloading": "Hardware offloading can improve network throughput",
		"filter.rule":                          "Large numbers of firewall rules can impact packet processing performance",
	}

	for _, f := range issues {
		report.AddFinding(mapSeverity(f.Severity), Finding{
			Type:           "performance",
			Title:          f.Issue,
			Description:    f.Description,
			Component:      f.Component,
			Recommendation: f.Recommendation,
			Reference:      referenceMap[f.Component],
		})
	}
}

// mapSeverity converts a common.Severity to the canonical processor Severity.
// Normalizes case and falls back to SeverityInfo for unrecognized values,
// which is critical for dynamic plugins that may return non-canonical severities.
func mapSeverity(s common.Severity) Severity {
	normalized := common.Severity(strings.ToLower(string(s)))
	if common.IsValidSeverity(normalized) {
		return Severity(normalized)
	}

	return SeverityInfo
}
