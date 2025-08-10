package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/markdown"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/parser"
	"github.com/charmbracelet/log"
)

// TestNATDisplayEnhancements tests that NAT mode and forwarding rules are prominently displayed
func TestNATDisplayEnhancements(t *testing.T) {
	tests := []struct {
		name     string
		xmlFile  string
		expected []string
	}{
		{
			name:    "automatic NAT mode",
			xmlFile: "./testdata/sample.config.2.xml",
			expected: []string{
				"## NAT Configuration",
				"### NAT Summary",
				"**NAT Mode**: `automatic`",
				"*(Automatic outbound NAT generation)*",
				"**NAT Reflection**: **Disabled** ✓",
				"**Port Forward State Sharing**: **Enabled**",
				"**Security Note**: NAT reflection is properly disabled",
			},
		},
		{
			name:    "advanced NAT mode with rules",
			xmlFile: "./testdata/sample.config.6.xml",
			expected: []string{
				"## NAT Configuration",
				"### NAT Summary",
				"**NAT Mode**: `advanced`",
				"*(Advanced outbound NAT rules)*",
				"**NAT Reflection**: **Disabled** ✓",
				"**Outbound Rules**: 51 configured",
				"### Outbound NAT Rules",
				"| # | Interface | Source | Destination | Target | Protocol | Description | Created By | Status |",
				"NAT MGMT to WAN1",
			},
		},
	}

	logger := log.NewWithOptions(nil, log.Options{Level: log.ErrorLevel})
	generator, err := markdown.NewMarkdownGenerator(logger)
	if err != nil {
		t.Fatalf("Failed to create markdown generator: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the configuration
			xmlFile, err := os.Open(tt.xmlFile)
			if err != nil {
				t.Fatalf("Failed to open XML file %s: %v", tt.xmlFile, err)
			}
			defer xmlFile.Close()

			xmlParser := parser.NewXMLParser()
			cfg, err := xmlParser.Parse(context.Background(), xmlFile)
			if err != nil {
				t.Fatalf("Failed to parse XML file %s: %v", tt.xmlFile, err)
			}

			// Generate markdown
			output, err := generator.Generate(context.Background(), cfg, markdown.Options{
				Format: markdown.FormatMarkdown,
				CustomFields: map[string]any{
					"IncludeTunables": false,
				},
			})
			if err != nil {
				t.Fatalf("Failed to generate markdown: %v", err)
			}

			// Check for expected content
			for _, expected := range tt.expected {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain '%s', but it was not found", expected)
					t.Logf("Generated output (first 2000 chars):\n%s", output[:min(2000, len(output))])
				}
			}

			// Ensure the output is well-structured
			if !strings.Contains(output, "## NAT Configuration") {
				t.Error("NAT section should have proper heading")
			}

			if !strings.Contains(output, "### NAT Summary") {
				t.Error("NAT section should have summary subsection")
			}

			if !strings.Contains(output, "### Outbound NAT Rules") {
				t.Error("NAT section should have rules subsection")
			}
		})
	}
}

// TestNATSummaryData tests that the NAT summary data is correctly populated
func TestNATSummaryData(t *testing.T) {
	// Create a test configuration
	cfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname:               "test-firewall",
			Domain:                 "test.local",
			DisableNATReflection:   "yes",
			PfShareForward:         1,
		},
		Nat: model.Nat{
			Outbound: model.Outbound{
				Mode: "manual",
				Rule: []model.NATRule{
					{
						Interface: model.InterfaceList{"wan"},
						Target:    "192.168.1.100",
						Descr:     "Test NAT rule",
					},
				},
			},
		},
	}

	// Test the NATSummary method
	natSummary := cfg.NATSummary()

	if natSummary.Mode != "manual" {
		t.Errorf("Expected NAT mode 'manual', got '%s'", natSummary.Mode)
	}

	if !natSummary.ReflectionDisabled {
		t.Error("Expected NAT reflection to be disabled")
	}

	if !natSummary.PfShareForward {
		t.Error("Expected PfShareForward to be enabled")
	}

	if len(natSummary.OutboundRules) != 1 {
		t.Errorf("Expected 1 outbound rule, got %d", len(natSummary.OutboundRules))
	}
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}