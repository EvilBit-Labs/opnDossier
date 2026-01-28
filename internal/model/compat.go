// Package model provides backward compatibility for the refactored schema and enrichment packages.
// This file re-exports types from internal/schema and internal/enrichment for consumers
// that import internal/model. New code should import the appropriate package directly.
//
// Package structure:
//   - internal/schema: Data structures for OPNsense configurations (XML/JSON/YAML)
//   - internal/enrichment: Business logic for analyzing and enriching configurations
//   - internal/model: Backward compatibility layer (this package)
//
// Migration guide:
//   - For schema types: import "github.com/EvilBit-Labs/opnDossier/internal/schema"
//   - For enrichment types: import "github.com/EvilBit-Labs/opnDossier/internal/enrichment"
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/enrichment"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// Schema type aliases - re-exported from internal/schema package

// BoolFlagAlias is an alias for schema.BoolFlag for backward compatibility.
//
// Deprecated: Use schema.BoolFlag directly.
type BoolFlagAlias = schema.BoolFlag

// ChangeMetaAlias is an alias for schema.ChangeMeta for backward compatibility.
//
// Deprecated: Use schema.ChangeMeta directly.
type ChangeMetaAlias = schema.ChangeMeta

// RuleLocationAlias is an alias for schema.RuleLocation for backward compatibility.
//
// Deprecated: Use schema.RuleLocation directly.
type RuleLocationAlias = schema.RuleLocation

// Enrichment type aliases - re-exported from internal/enrichment package

// EnrichedOpnSenseDocumentAlias is an alias for enrichment.EnrichedOpnSenseDocument.
//
// Deprecated: Use enrichment.EnrichedOpnSenseDocument directly.
type EnrichedOpnSenseDocumentAlias = enrichment.EnrichedOpnSenseDocument

// StatisticsAlias is an alias for enrichment.Statistics.
//
// Deprecated: Use enrichment.Statistics directly.
type StatisticsAlias = enrichment.Statistics

// InterfaceStatisticsAlias is an alias for enrichment.InterfaceStatistics.
//
// Deprecated: Use enrichment.InterfaceStatistics directly.
type InterfaceStatisticsAlias = enrichment.InterfaceStatistics

// DHCPScopeStatisticsAlias is an alias for enrichment.DHCPScopeStatistics.
//
// Deprecated: Use enrichment.DHCPScopeStatistics directly.
type DHCPScopeStatisticsAlias = enrichment.DHCPScopeStatistics

// ServiceStatisticsAlias is an alias for enrichment.ServiceStatistics.
//
// Deprecated: Use enrichment.ServiceStatistics directly.
type ServiceStatisticsAlias = enrichment.ServiceStatistics

// StatisticsSummaryAlias is an alias for enrichment.StatisticsSummary.
//
// Deprecated: Use enrichment.StatisticsSummary directly.
type StatisticsSummaryAlias = enrichment.StatisticsSummary

// AnalysisAlias is an alias for enrichment.Analysis.
//
// Deprecated: Use enrichment.Analysis directly.
type AnalysisAlias = enrichment.Analysis

// DeadRuleFindingAlias is an alias for enrichment.DeadRuleFinding.
//
// Deprecated: Use enrichment.DeadRuleFinding directly.
type DeadRuleFindingAlias = enrichment.DeadRuleFinding

// UnusedInterfaceFindingAlias is an alias for enrichment.UnusedInterfaceFinding.
//
// Deprecated: Use enrichment.UnusedInterfaceFinding directly.
type UnusedInterfaceFindingAlias = enrichment.UnusedInterfaceFinding

// SecurityFindingAlias is an alias for enrichment.SecurityFinding.
//
// Deprecated: Use enrichment.SecurityFinding directly.
type SecurityFindingAlias = enrichment.SecurityFinding

// PerformanceFindingAlias is an alias for enrichment.PerformanceFinding.
//
// Deprecated: Use enrichment.PerformanceFinding directly.
type PerformanceFindingAlias = enrichment.PerformanceFinding

// ConsistencyFindingAlias is an alias for enrichment.ConsistencyFinding.
//
// Deprecated: Use enrichment.ConsistencyFinding directly.
type ConsistencyFindingAlias = enrichment.ConsistencyFinding

// SecurityAssessmentAlias is an alias for enrichment.SecurityAssessment.
//
// Deprecated: Use enrichment.SecurityAssessment directly.
type SecurityAssessmentAlias = enrichment.SecurityAssessment

// PerformanceMetricsAlias is an alias for enrichment.PerformanceMetrics.
//
// Deprecated: Use enrichment.PerformanceMetrics directly.
type PerformanceMetricsAlias = enrichment.PerformanceMetrics

// ComplianceChecksAlias is an alias for enrichment.ComplianceChecks.
//
// Deprecated: Use enrichment.ComplianceChecks directly.
type ComplianceChecksAlias = enrichment.ComplianceChecks

// Function re-exports from enrichment package

// EnrichDocumentFromEnrichment is an alias for enrichment.EnrichDocument.
//
// Deprecated: Use enrichment.EnrichDocument directly.
var EnrichDocumentFromEnrichment = enrichment.EnrichDocument
