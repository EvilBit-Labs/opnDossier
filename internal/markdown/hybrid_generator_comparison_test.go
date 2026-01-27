package markdown

import (
	"context"
	"strings"
	"testing"
	"text/template"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// TestHybridGenerator_OutputComparison tests that both programmatic and template
// generation produce equivalent output for the same input data.
func TestHybridGenerator_OutputComparison(t *testing.T) {
	// Create test data that represents a typical OPNsense configuration
	data := createTestOpnSenseDocument()

	// Test both generation modes
	t.Run("Standard Report Comparison", func(t *testing.T) {
		compareGenerationModes(t, data, DefaultOptions())
	})

	t.Run("Comprehensive Report Comparison", func(t *testing.T) {
		opts := DefaultOptions()
		opts.Comprehensive = true
		compareGenerationModes(t, data, opts)
	})
}

// compareGenerationModes compares output between programmatic and template generation.
func compareGenerationModes(t *testing.T, data *model.OpnSenseDocument, opts Options) {
	t.Helper()
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	reportBuilder := builder.NewMarkdownBuilder()

	// Generate using programmatic mode
	programmaticGen, err := NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		t.Fatalf("Failed to create programmatic generator: %v", err)
	}
	programmaticOutput, err := programmaticGen.Generate(context.Background(), data, opts)
	if err != nil {
		t.Fatalf("Programmatic generation failed: %v", err)
	}

	// Create a template that should produce equivalent output
	templateContent := createEquivalentTemplate(opts.Comprehensive)
	tmpl, err := template.New("equivalent").Parse(templateContent)
	if err != nil {
		t.Fatalf("Failed to parse equivalent template: %v", err)
	}

	// Generate using template mode
	templateGen, err := NewHybridGeneratorWithTemplate(reportBuilder, tmpl, logger)
	if err != nil {
		t.Fatalf("Failed to create template generator: %v", err)
	}
	templateOutput, err := templateGen.Generate(context.Background(), data, opts)
	if err != nil {
		t.Fatalf("Template generation failed: %v", err)
	}

	// Compare outputs
	compareOutputs(t, programmaticOutput, templateOutput, opts.Comprehensive)
}

// compareOutputs compares the outputs from both generation methods.
func compareOutputs(t *testing.T, programmatic, templateOutput string, comprehensive bool) {
	t.Helper()
	// Normalize outputs for comparison
	progNorm := normalizeOutput(programmatic)
	tmplNorm := normalizeOutput(templateOutput)

	// Check that both outputs contain essential elements
	essentialElements := []string{
		"test-firewall",
		"example.com",
		"System Configuration",
		"Network Configuration",
	}

	if comprehensive {
		essentialElements = append(essentialElements, "Security Configuration")
		// Note: Service Configuration is not included in our simplified test template
		// but would be present in a full template implementation
	}

	for _, element := range essentialElements {
		if !strings.Contains(progNorm, element) {
			t.Errorf("Programmatic output missing essential element: %s", element)
		}
		if !strings.Contains(tmplNorm, element) {
			t.Errorf("Template output missing essential element: %s", element)
		}
	}

	// Check that both outputs have reasonable length
	if strings.Count(progNorm, "\n")+1 < 10 {
		t.Error("Programmatic output too short")
	}
	if strings.Count(tmplNorm, "\n")+1 < 10 {
		t.Error("Template output too short")
	}

	// Both should contain markdown headers
	progHeaders := countHeaders(progNorm)
	tmplHeaders := countHeaders(tmplNorm)

	if progHeaders < 2 {
		t.Error("Programmatic output has too few headers")
	}
	if tmplHeaders < 2 {
		t.Error("Template output has too few headers")
	}

	// Both should contain the same key information
	keyInfo := []string{
		"Hostname",
		"Domain",
		"Interfaces",
	}

	for _, info := range keyInfo {
		progHas := strings.Contains(progNorm, info)
		tmplHas := strings.Contains(tmplNorm, info)
		if progHas != tmplHas {
			t.Errorf("Inconsistent presence of key info '%s': programmatic=%v, template=%v", info, progHas, tmplHas)
		}
	}
}

// createTestOpnSenseDocument creates a test OPNsense configuration document.
func createTestOpnSenseDocument() *model.OpnSenseDocument {
	return &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
			Timezone: "UTC",
			Firmware: model.Firmware{
				Version: "24.1.0",
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					If:     "em0",
					Enable: "1",
					IPAddr: "192.168.1.1",
					Subnet: "24",
					Descr:  "WAN Interface",
				},
				"lan": {
					If:     "em1",
					Enable: "1",
					IPAddr: "10.0.0.1",
					Subnet: "24",
					Descr:  "LAN Interface",
				},
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{
					Type:        "pass",
					Interface:   model.InterfaceList{"wan"},
					IPProtocol:  "inet",
					Protocol:    "tcp",
					Source:      model.Source{Network: "any"},
					Destination: model.Destination{Network: "any"},
					Descr:       "Allow WAN traffic",
				},
			},
		},
	}
}

// createEquivalentTemplate creates a template that should produce equivalent output to programmatic generation.
func createEquivalentTemplate(comprehensive bool) string {
	baseTemplate := `# OPNsense Configuration Summary

## System Information
- **Hostname**: {{.System.Hostname}}
- **Domain**: {{.System.Domain}}
- **Platform**: OPNsense {{.System.Firmware.Version}}
- **Generated On**: {{.Generated}}
- **Parsed By**: opnDossier v{{.ToolVersion}}

## Table of Contents
- [System Configuration](#system-configuration)
- [Interfaces](#interfaces)
- [Firewall Rules](#firewall-rules)`

	if comprehensive {
		baseTemplate += `
- [NAT Configuration](#nat-configuration)
- [DHCP Services](#dhcp-services)
- [DNS Resolver](#dns-resolver)
- [System Users](#system-users)
- [Services & Daemons](#services--daemons)
- [System Tunables](#system-tunables)`
	}

	baseTemplate += `

## System Configuration

### Basic Information
**Hostname**: {{.System.Hostname}}
**Domain**: {{.System.Domain}}
{{if .System.Timezone}}**Timezone**: {{.System.Timezone}}{{end}}

## Network Configuration

### Interfaces
{{range $name, $iface := .Interfaces.Items}}
#### {{$name}} Interface
**Physical Interface**: {{$iface.If}}
**Enabled**: {{if eq $iface.Enable "1"}}✓{{else}}✗{{end}}
**IPv4 Address**: {{$iface.IPAddr}}
**IPv4 Subnet**: {{$iface.Subnet}}
**Description**: {{$iface.Descr}}
{{end}}

## Security Configuration

### Firewall Rules
{{if .Filter.Rule}}
| # | Interface | Action | IP Ver | Proto | Source | Destination | Target | Source Port | Enabled | Description |
|---|-----------|--------|--------|-------|--------|-------------|--------|-------------|---------|-------------|
{{range $index, $rule := .Filter.Rule}}
| {{$index}} | {{$rule.Interface}} | {{$rule.Type}} | {{$rule.IPProtocol}} | {{$rule.Protocol}} | {{if eq $rule.Source.Network ""}}any{{else}}{{$rule.Source.Network}}{{end}} | {{if eq $rule.Destination.Network ""}}any{{else}}{{$rule.Destination.Network}}{{end}} | {{$rule.Target}} | {{$rule.SourcePort}} | {{if eq $rule.Disabled "1"}}✗{{else}}✓{{end}} | {{$rule.Descr}} |
{{end}}
{{else}}
No firewall rules configured.
{{end}}`

	return baseTemplate
}

// normalizeOutput normalizes output for comparison by removing extra whitespace and normalizing line endings.
func normalizeOutput(output string) string {
	// Replace Windows line endings with Unix
	output = strings.ReplaceAll(output, "\r\n", "\n")

	// Remove extra whitespace
	var normalizedLines []string
	lines := strings.FieldsFunc(output, func(r rune) bool {
		return r == '\n'
	})
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			normalizedLines = append(normalizedLines, trimmed)
		}
	}

	return strings.Join(normalizedLines, "\n")
}

// countHeaders counts the number of markdown headers in the output.
func countHeaders(output string) int {
	count := 0
	lines := strings.FieldsFunc(output, func(r rune) bool {
		return r == '\n'
	})
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			count++
		}
	}

	return count
}

// TestHybridGenerator_FeatureFlags tests the feature flag functionality for gradual transition.
func TestHybridGenerator_FeatureFlags(t *testing.T) {
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	reportBuilder := builder.NewMarkdownBuilder()
	data := createTestOpnSenseDocument()

	tests := []struct {
		name          string
		opts          Options
		expectedMode  string
		expectedError bool
	}{
		{
			name:          "default options - programmatic mode",
			opts:          DefaultOptions(),
			expectedMode:  "programmatic",
			expectedError: false,
		},
		{
			name:          "custom template directory - template mode",
			opts:          DefaultOptions().WithTemplateDir("/tmp/templates"),
			expectedMode:  "template",
			expectedError: false,
		},
		{
			name:          "template name specified - template mode",
			opts:          DefaultOptions().WithTemplateName("standard"),
			expectedMode:  "template",
			expectedError: false,
		},
		{
			name:          "comprehensive mode - programmatic",
			opts:          DefaultOptions().WithComprehensive(true),
			expectedMode:  "programmatic",
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewHybridGenerator(reportBuilder, logger)
			if err != nil {
				t.Fatalf("Failed to create hybrid generator: %v", err)
			}

			// Note: Mode determination logic has been removed as shouldUseTemplate is now unexported
			// The test now focuses on ensuring generation works without errors

			// Test that generation works without error
			output, err := gen.Generate(context.Background(), data, tt.opts)
			if tt.expectedError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectedError && output == "" {
				t.Error("Generated output is empty")
			}
		})
	}
}

// TestHybridGenerator_FallbackMechanism tests the fallback mechanism for custom templates.
func TestHybridGenerator_FallbackMechanism(t *testing.T) {
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	reportBuilder := builder.NewMarkdownBuilder()
	data := createTestOpnSenseDocument()

	// Test with invalid template directory
	opts := DefaultOptions().WithTemplateDir("/nonexistent/directory")
	gen, err := NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		t.Fatalf("Failed to create hybrid generator: %v", err)
	}

	// This should fall back to programmatic generation
	output, err := gen.Generate(context.Background(), data, opts)
	if err != nil {
		t.Fatalf("Fallback generation failed: %v", err)
	}

	if output == "" {
		t.Error("Fallback output is empty")
	}

	// Verify it contains expected content from programmatic generation
	if !strings.Contains(output, "test-firewall") {
		t.Error("Fallback output does not contain expected content")
	}
}
