// Package model re-exports types from internal/enrichment for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/enrichment"
)

// Enrichment constants re-exported from enrichment package.
const (
	// ProtocolHTTPS represents the HTTPS protocol identifier.
	ProtocolHTTPS = enrichment.ProtocolHTTPS
	// ProtocolHTTP represents the HTTP protocol identifier.
	ProtocolHTTP = enrichment.ProtocolHTTP
	// RuleTypePass represents a firewall pass rule.
	RuleTypePass = enrichment.RuleTypePass
	// RuleTypeBlock represents a firewall block rule.
	RuleTypeBlock = enrichment.RuleTypeBlock
	// NetworkAny represents the "any" network in firewall rules.
	NetworkAny = enrichment.NetworkAny
	// MaxComplexityScore is the maximum achievable complexity score.
	MaxComplexityScore = enrichment.MaxComplexityScore
	// MaxSecurityScore is the maximum achievable security score.
	MaxSecurityScore = enrichment.MaxSecurityScore
	// MaxComplianceScore is the maximum achievable compliance score.
	MaxComplianceScore = enrichment.MaxComplianceScore
	// RuleComplexityWeight is the complexity scoring weight per firewall rule.
	RuleComplexityWeight = enrichment.RuleComplexityWeight
	// ServiceComplexityWeight is the complexity scoring weight per enabled service.
	ServiceComplexityWeight = enrichment.ServiceComplexityWeight
	// MaxRulesThreshold is the rule count threshold for complexity calculations.
	MaxRulesThreshold = enrichment.MaxRulesThreshold
	// BaseSecurityScore is the starting security score before deductions.
	BaseSecurityScore = enrichment.BaseSecurityScore
	// BaseResourceUsage is the base resource usage estimate.
	BaseResourceUsage = enrichment.BaseResourceUsage
)

// EnrichedOpnSenseDocument extends OpnSenseDocument with calculated fields and analysis data.
type EnrichedOpnSenseDocument = enrichment.EnrichedOpnSenseDocument

// Statistics contains calculated statistics about the configuration.
type Statistics = enrichment.Statistics

// InterfaceStatistics contains detailed statistics for a single interface.
type InterfaceStatistics = enrichment.InterfaceStatistics

// DHCPScopeStatistics contains statistics for a DHCP scope.
type DHCPScopeStatistics = enrichment.DHCPScopeStatistics

// ServiceStatistics contains statistics for a service.
type ServiceStatistics = enrichment.ServiceStatistics

// StatisticsSummary contains summary statistics.
type StatisticsSummary = enrichment.StatisticsSummary

// Analysis contains analysis findings and insights.
type Analysis = enrichment.Analysis

// DeadRuleFinding represents a dead rule finding.
type DeadRuleFinding = enrichment.DeadRuleFinding

// UnusedInterfaceFinding represents an unused interface finding.
type UnusedInterfaceFinding = enrichment.UnusedInterfaceFinding

// SecurityFinding represents a security finding.
type SecurityFinding = enrichment.SecurityFinding

// PerformanceFinding represents a performance finding.
type PerformanceFinding = enrichment.PerformanceFinding

// ConsistencyFinding represents a consistency finding.
type ConsistencyFinding = enrichment.ConsistencyFinding

// SecurityAssessment contains security assessment data.
type SecurityAssessment = enrichment.SecurityAssessment

// PerformanceMetrics contains performance metrics.
type PerformanceMetrics = enrichment.PerformanceMetrics

// ComplianceChecks contains compliance check results.
type ComplianceChecks = enrichment.ComplianceChecks

// EnrichDocument returns an EnrichedOpnSenseDocument containing computed statistics,
// analysis findings, security assessment, performance metrics, and compliance checks.
// Returns nil if the input configuration is nil.
func EnrichDocument(cfg *OpnSenseDocument) *EnrichedOpnSenseDocument {
	return enrichment.EnrichDocument(cfg)
}
