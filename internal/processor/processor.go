// Package processor provides interfaces and types for processing OPNsense configurations.
// It enables flexible analysis of OPNsense configurations through an options pattern,
// allowing features like statistics generation, dead-rule detection, and other analyses
// to be enabled independently.
package processor

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/unclesp1d3r/opnFocus/internal/markdown"
	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// Processor defines the interface for processing OPNsense configurations.
// It provides a flexible way to analyze configurations with configurable options.
type Processor interface {
	// Process analyzes the given OPNsense configuration and returns a comprehensive report.
	// The context allows for cancellation and timeout control.
	// Options can be used to enable specific analysis features.
	Process(ctx context.Context, cfg *model.OpnSenseDocument, opts ...Option) (*Report, error)
}

// CoreProcessor implements the Processor interface with normalize, validate, analyze, and transform capabilities.
type CoreProcessor struct {
	validator *validator.Validate
	generator markdown.Generator
}

// NewCoreProcessor returns a new CoreProcessor instance with a validator and a markdown generator initialized.
// Returns an error if the markdown generator cannot be created.
func NewCoreProcessor() (*CoreProcessor, error) {
	generator, err := markdown.NewMarkdownGenerator(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create markdown generator: %w", err)
	}

	return &CoreProcessor{
		validator: validator.New(),
		generator: generator,
	}, nil
}

// Process analyzes the given OPNsense configuration and returns a comprehensive report.
func (p *CoreProcessor) Process(ctx context.Context, cfg *model.OpnSenseDocument, opts ...Option) (*Report, error) {
	if cfg == nil {
		return nil, ErrConfigurationNil
	}

	// Apply options to get configuration
	config := DefaultConfig()
	config.ApplyOptions(opts...)

	// Phase 1: Normalize the configuration
	normalizedCfg := p.normalize(cfg)

	// Phase 2: Validate the configuration
	validationErrors := p.validate(normalizedCfg)

	// Create the report
	report := NewReport(normalizedCfg, *config)

	// Add validation errors as findings
	for _, validationErr := range validationErrors {
		report.AddFinding(SeverityHigh, Finding{
			Type:        "validation",
			Title:       "Configuration Validation Error",
			Description: validationErr.Error(),
			Component:   validationErr.Field,
		})
	}

	// Phase 3: Analyze the configuration
	p.analyze(ctx, normalizedCfg, config, report)

	return report, nil
}

// Transform converts the report to the specified format.
func (p *CoreProcessor) Transform(ctx context.Context, report *Report, format string) (string, error) {
	switch strings.ToLower(format) {
	case "json":
		return report.ToJSON()
	case "yaml":
		return p.toYAML(report)
	case "markdown":
		return p.toMarkdown(ctx, report)
	default:
		return "", fmt.Errorf("unsupported format: %w", &UnsupportedFormatError{Format: format})
	}
}

// Option represents a configuration option for the processor.
// This follows the functional options pattern to allow flexible configuration.
type Option func(*Config)

// Config holds the configuration for the processor.
type Config struct {
	// EnableStats controls whether to generate configuration statistics
	EnableStats bool
	// EnableDeadRuleCheck controls whether to analyze for unused/dead rules
	EnableDeadRuleCheck bool
	// EnableSecurityAnalysis controls whether to perform security analysis
	EnableSecurityAnalysis bool
	// EnablePerformanceAnalysis controls whether to analyze performance aspects
	EnablePerformanceAnalysis bool
	// EnableComplianceCheck controls whether to check compliance with best practices
	EnableComplianceCheck bool
}

// WithStats enables statistics generation in the processor.
func WithStats() Option {
	return func(config *Config) {
		config.EnableStats = true
	}
}

// WithDeadRuleCheck enables dead rule detection in the processor.
func WithDeadRuleCheck() Option {
	return func(config *Config) {
		config.EnableDeadRuleCheck = true
	}
}

// WithSecurityAnalysis enables security analysis in the processor.
func WithSecurityAnalysis() Option {
	return func(config *Config) {
		config.EnableSecurityAnalysis = true
	}
}

// WithPerformanceAnalysis enables performance analysis in the processor.
func WithPerformanceAnalysis() Option {
	return func(config *Config) {
		config.EnablePerformanceAnalysis = true
	}
}

// WithComplianceCheck enables compliance checking in the processor.
func WithComplianceCheck() Option {
	return func(config *Config) {
		config.EnableComplianceCheck = true
	}
}

// WithAllFeatures enables all available analysis features.
func WithAllFeatures() Option {
	return func(config *Config) {
		config.EnableStats = true
		config.EnableDeadRuleCheck = true
		config.EnableSecurityAnalysis = true
		config.EnablePerformanceAnalysis = true
		config.EnableComplianceCheck = true
	}
}

// DefaultConfig returns a Config with default settings.
func DefaultConfig() *Config {
	return &Config{
		EnableStats:               true,
		EnableDeadRuleCheck:       false,
		EnableSecurityAnalysis:    false,
		EnablePerformanceAnalysis: false,
		EnableComplianceCheck:     false,
	}
}

// ApplyOptions applies the given options to the configuration.
func (c *Config) ApplyOptions(opts ...Option) {
	for _, opt := range opts {
		opt(c)
	}
}
