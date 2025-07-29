package processor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/unclesp1d3r/opnFocus/internal/constants"
	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// ExampleUsage demonstrates various ways to process an OpnSense configuration document using the processor, including basic, security-focused, and comprehensive analyses, as well as handling custom timeouts and reporting in multiple formats.
func ExampleUsage(cfg *model.OpnSenseDocument) {
	// Create a processor instance
	processor := NewExampleProcessor()

	// Set up context with timeout for long-running analysis
	ctx, cancel := context.WithTimeout(context.Background(), constants.DefaultProcessingTimeout)
	defer cancel()

	// Example 1: Basic processing with default options
	fmt.Println("=== Basic Analysis ===")
	report, err := processor.Process(ctx, cfg)
	if err != nil {
		fmt.Printf("Error during basic analysis: %v\n", err)
		return
	}

	fmt.Println(report.Summary())
	fmt.Printf("Total findings: %d\n", report.TotalFindings())
	if report.HasCriticalFindings() {
		fmt.Printf("⚠️  Critical issues found: %d\n", len(report.Findings.Critical))
	}
	fmt.Println()

	// Example 2: Security-focused analysis
	fmt.Println("=== Security Analysis ===")
	securityReport, err := processor.Process(ctx, cfg,
		WithStats(),
		WithSecurityAnalysis(),
		WithComplianceCheck(),
	)
	if err != nil {
		fmt.Printf("Error during security analysis: %v\n", err)
		return
	}

	// Print security-specific findings
	if len(securityReport.Findings.High) > 0 {
		fmt.Println("High severity security findings:")
		for _, finding := range securityReport.Findings.High {
			if finding.Type == FindingTypeSecurity {
				fmt.Printf("- %s: %s\n", finding.Title, finding.Description)
			}
		}
	}
	fmt.Println()

	// Example 3: Comprehensive analysis with all features
	fmt.Println("=== Comprehensive Analysis ===")
	fullReport, err := processor.Process(ctx, cfg, WithAllFeatures())
	if err != nil {
		fmt.Printf("Error during comprehensive analysis: %v\n", err)
		return
	}

	// Generate different output formats
	fmt.Println("Generating reports in multiple formats...")

	// Markdown report
	markdown := fullReport.ToMarkdown()
	fmt.Printf("Markdown report generated (%d characters)\n", len(markdown))

	// JSON report
	jsonStr, err := fullReport.ToJSON()
	if err != nil {
		fmt.Printf("Error generating JSON: %v\n", err)
	} else {
		fmt.Printf("JSON report generated (%d characters)\n", len(jsonStr))
	}

	// Summary for quick overview
	summary := fullReport.Summary()
	fmt.Printf("Summary: %s\n", summary)

	// Example 4: Processing with custom timeout and error handling
	fmt.Println("\n=== Analysis with Custom Timeout ===")
	quickCtx, quickCancel := context.WithTimeout(context.Background(), constants.QuickProcessingTimeout)
	defer quickCancel()

	quickReport, err := processor.Process(quickCtx, cfg, WithDeadRuleCheck())
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Println("Analysis timed out - configuration may be too large")
		} else {
			fmt.Printf("Error during quick analysis: %v\n", err)
		}
		return
	}

	// Check for maintenance-related findings
	maintenanceIssues := 0
	for _, finding := range quickReport.Findings.Low {
		if finding.Type == "maintenance" {
			maintenanceIssues++
		}
	}
	fmt.Printf("Found %d maintenance issues\n", maintenanceIssues)
}

// ProcessConfigFromFile loads an OpnSense configuration from the specified file path, processes it with all analysis features enabled, and prints a summary of the results.
// Returns an error if processing fails.
func ProcessConfigFromFile(configPath string) error {
	// This would typically involve:
	// 1. Loading the configuration file
	// 2. Parsing it into model.OpnSenseDocument
	// 3. Processing with the processor
	// 4. Outputting results

	fmt.Printf("Processing configuration from: %s\n", configPath)

	// Placeholder - in real implementation you would:
	// cfg, err := parseConfigFile(configPath)
	// if err != nil {
	//     return fmt.Errorf("failed to parse config: %w", err)
	// }

	// For demonstration, create a minimal config
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "example-firewall",
			Domain:   "example.com",
		},
	}

	processor := NewExampleProcessor()
	ctx := context.Background()

	report, err := processor.Process(ctx, cfg, WithAllFeatures())
	if err != nil {
		return fmt.Errorf("processing failed: %w", err)
	}

	// In a real scenario, you might:
	// - Save the report to a file
	// - Send it via email
	// - Store it in a database
	// - Display it in a web interface

	fmt.Println("Configuration processed successfully")
	fmt.Printf("Generated at: %s\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Printf("Total findings: %d\n", report.TotalFindings())

	return nil
}

// CustomProcessorExample shows how to create a custom processor implementation
// that extends or modifies the behavior of the example processor.
type CustomProcessorExample struct {
	*ExampleProcessor
	customChecks []CustomCheck
}

// CustomCheck represents a custom analysis check.
type CustomCheck struct {
	Name        string
	Description string
	CheckFunc   func(*model.OpnSenseDocument) []Finding
}

// NewCustomProcessor returns a CustomProcessorExample that applies the provided custom checks in addition to the standard processing.
func NewCustomProcessor(customChecks []CustomCheck) *CustomProcessorExample {
	return &CustomProcessorExample{
		ExampleProcessor: NewExampleProcessor(),
		customChecks:     customChecks,
	}
}

// Process extends the base processor with custom checks.
func (p *CustomProcessorExample) Process(ctx context.Context, cfg *model.OpnSenseDocument, opts ...Option) (*Report, error) {
	// First run the standard processing
	report, err := p.ExampleProcessor.Process(ctx, cfg, opts...)
	if err != nil {
		return nil, err
	}

	// Apply custom checks
	for _, check := range p.customChecks {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		findings := check.CheckFunc(cfg)
		for _, finding := range findings {
			// Add custom findings as info level by default
			report.AddFinding(SeverityInfo, finding)
		}
	}

	return report, nil
}

// ExampleCustomCheck returns a custom check that detects if the OpnSense configuration is using the default theme.
// The check produces a finding if no specific theme is set, recommending that a theme be configured for consistency.
func ExampleCustomCheck() CustomCheck {
	return CustomCheck{
		Name:        "Theme Check",
		Description: "Validates the configured theme",
		CheckFunc: func(cfg *model.OpnSenseDocument) []Finding {
			var findings []Finding

			if cfg.Theme == "" {
				findings = append(findings, Finding{
					Type:           "ui",
					Title:          "Default Theme in Use",
					Description:    "The system is using the default theme.",
					Recommendation: "Consider setting a specific theme for consistency.",
					Component:      "webgui",
				})
			}

			return findings
		},
	}
}
