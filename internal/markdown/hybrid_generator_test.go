package markdown

import (
	"context"
	"errors"
	"strings"
	"testing"
	"text/template"

	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

func TestNewHybridGenerator(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Test with nil logger
	gen, err := NewHybridGenerator(reportBuilder, nil)
	if err != nil {
		t.Fatalf("NewHybridGenerator failed: %v", err)
	}
	if gen == nil {
		t.Fatal("NewHybridGenerator returned nil")
	}
	// Note: Internal fields are now unexported for proper encapsulation

	// Test with logger
	gen, err = NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		t.Fatalf("NewHybridGenerator failed: %v", err)
	}
	if gen == nil {
		t.Fatal("NewHybridGenerator returned nil")
	}
	// Note: Internal fields are now unexported for proper encapsulation
}

func TestNewHybridGeneratorWithTemplate(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	tmpl := template.New("test")

	// Test with nil logger
	gen, err := NewHybridGeneratorWithTemplate(reportBuilder, tmpl, nil)
	if err != nil {
		t.Fatalf("NewHybridGeneratorWithTemplate failed: %v", err)
	}
	if gen == nil {
		t.Fatal("NewHybridGeneratorWithTemplate returned nil")
	}
	// Note: Internal fields are now unexported for proper encapsulation

	// Test with logger
	gen, err = NewHybridGeneratorWithTemplate(reportBuilder, tmpl, logger)
	if err != nil {
		t.Fatalf("NewHybridGeneratorWithTemplate failed: %v", err)
	}
	if gen == nil {
		t.Fatal("NewHybridGeneratorWithTemplate returned nil")
	}
	// Note: Internal fields are now unexported for proper encapsulation
}

func TestHybridGenerator_Generate_Programmatic(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	gen, err := NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		t.Fatalf("Failed to create hybrid generator: %v", err)
	}

	// Create test data
	data := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
	}

	opts := DefaultOptions()

	// Test programmatic generation (default)
	output, err := gen.Generate(context.Background(), data, opts)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if output == "" {
		t.Error("Generated output is empty")
	}

	// Verify it contains expected content
	if !strings.Contains(output, "test-firewall") {
		t.Error("Generated output does not contain hostname")
	}
	if !strings.Contains(output, "example.com") {
		t.Error("Generated output does not contain domain")
	}
}

func TestHybridGenerator_Generate_Template(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create a simple test template
	tmplContent := `# Test Report
Hostname: {{.System.Hostname}}
Domain: {{.System.Domain}}
Generated: {{.Generated}}
ToolVersion: {{.ToolVersion}}`

	tmpl, err := template.New("test").Parse(tmplContent)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}

	gen, err := NewHybridGeneratorWithTemplate(reportBuilder, tmpl, logger)
	if err != nil {
		t.Fatalf("Failed to create hybrid generator with template: %v", err)
	}

	// Create test data
	data := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
	}

	opts := DefaultOptions()
	opts.CustomFields["Generated"] = "2024-01-01T00:00:00Z"
	opts.CustomFields["ToolVersion"] = "1.0.0"

	// Test template generation
	output, err := gen.Generate(context.Background(), data, opts)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if output == "" {
		t.Error("Generated output is empty")
	}

	// Verify it contains expected template content
	if !strings.Contains(output, "# Test Report") {
		t.Error("Generated output does not contain template title")
	}
	if !strings.Contains(output, "Hostname: test-firewall") {
		t.Error("Generated output does not contain hostname from template")
	}
	if !strings.Contains(output, "Domain: example.com") {
		t.Error("Generated output does not contain domain from template")
	}
}

func TestHybridGenerator_Generate_Comprehensive(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	gen, err := NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		t.Fatalf("Failed to create hybrid generator: %v", err)
	}

	// Create test data
	data := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
	}

	opts := DefaultOptions()
	opts.Comprehensive = true

	// Test comprehensive programmatic generation
	output, err := gen.Generate(context.Background(), data, opts)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if output == "" {
		t.Error("Generated output is empty")
	}

	// Verify it contains expected content
	if !strings.Contains(output, "test-firewall") {
		t.Error("Generated output does not contain hostname")
	}
	if !strings.Contains(output, "example.com") {
		t.Error("Generated output does not contain domain")
	}
}

// Disabled: accesses unexported method shouldUseTemplate
// This test should be moved to the converter package if needed
/*
func TestHybridGenerator_shouldUseTemplate(t *testing.T) {
	builder := builder.NewMarkdownBuilder()
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
		gen, err := NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		t.Fatalf("Failed to create hybrid generator: %v", err)
	}

	tests := []struct {
		name     string
		template *template.Template
		opts     Options
		expected bool
	}{
		{
			name:     "no template, no template options - should use programmatic",
			template: nil,
			opts:     DefaultOptions(),
			expected: false,
		},
		{
			name:     "custom template provided - should use template",
			template: template.New("test"),
			opts:     DefaultOptions(),
			expected: true,
		},
		{
			name:     "template name specified - should use template",
			template: nil,
			opts:     DefaultOptions().WithTemplateName("standard"),
			expected: true,
		},
		{
			name:     "template directory specified - should use template",
			template: nil,
			opts:     DefaultOptions().WithTemplateDir("/tmp/templates"),
			expected: true,
		},
		{
			name:     "markdown format - should allow template usage",
			template: nil,
			opts:     DefaultOptions().WithFormat(FormatMarkdown),
			expected: false, // No template options, so programmatic
		},
		{
			name:     "markdown format with template name - should use template",
			template: nil,
			opts:     DefaultOptions().WithFormat(FormatMarkdown).WithTemplateName("standard"),
			expected: true,
		},
		{
			name:     "json format - should force programmatic generation",
			template: template.New("test"), // Even with template
			opts:     DefaultOptions().WithFormat(FormatJSON),
			expected: false,
		},
		{
			name:     "yaml format - should force programmatic generation",
			template: template.New("test"), // Even with template
			opts:     DefaultOptions().WithFormat(FormatYAML),
			expected: false,
		},
		{
			name:     "empty format - should default to markdown behavior",
			template: nil,
			opts:     Options{}, // Empty options, format is empty string
			expected: false,     // No template options, so programmatic
		},
		{
			name:     "empty format with template - should use template",
			template: template.New("test"),
			opts:     Options{}, // Empty options, format is empty string
			expected: true,
		},
		{
			name:     "UseTemplateEngine explicitly set to true - should use template",
			template: nil,
			opts:     DefaultOptions().WithUseTemplateEngine(true),
			expected: true,
		},
		{
			name:     "UseTemplateEngine explicitly set to false but template provided - should still use template",
			template: template.New("test"), // Template takes precedence
			opts:     DefaultOptions().WithUseTemplateEngine(false),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen.template = tt.template
			result := gen.shouldUseTemplate(tt.opts)
			if result != tt.expected {
				t.Errorf("shouldUseTemplate() = %v, want %v", result, tt.expected)
			}
		})
	}
}
*/

func TestHybridGenerator_Generate_NilData(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, loggerErr := log.New(log.Config{})
	if loggerErr != nil {
		t.Fatalf("Failed to create logger: %v", loggerErr)
	}
	gen, err := NewHybridGenerator(reportBuilder, logger)
	if err != nil {
		t.Fatalf("Failed to create hybrid generator: %v", err)
	}

	opts := DefaultOptions()

	// Test with nil data
	_, generateErr := gen.Generate(context.Background(), nil, opts)
	if generateErr == nil {
		t.Error("Expected error for nil data")
	}
	if !errors.Is(generateErr, converter.ErrNilOpnSenseDocument) {
		t.Errorf("Expected ErrNilOpnSenseDocument, got %v", generateErr)
	}
}

func TestHybridGenerator_Generate_NoBuilder(t *testing.T) {
	logger, loggerErr := log.New(log.Config{})
	if loggerErr != nil {
		t.Fatalf("Failed to create logger: %v", loggerErr)
	}
	gen, genErr := NewHybridGenerator(nil, logger)
	if genErr != nil {
		t.Fatalf("Failed to create hybrid generator: %v", genErr)
	}

	data := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
		},
	}

	opts := DefaultOptions()

	// Test with no builder
	_, err := gen.Generate(context.Background(), data, opts)
	if err == nil {
		t.Error("Expected error for no builder")
	}
	if !strings.Contains(err.Error(), "no report builder available") {
		t.Errorf("Expected error about missing builder, got %v", err)
	}
}

func TestHybridGenerator_SetAndGetTemplate(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, loggerErr := log.New(log.Config{})
	if loggerErr != nil {
		t.Fatalf("Failed to create logger: %v", loggerErr)
	}
	gen, genErr := NewHybridGenerator(reportBuilder, logger)
	if genErr != nil {
		t.Fatalf("Failed to create hybrid generator: %v", genErr)
	}

	// Test initial state
	if gen.GetTemplate() != nil {
		t.Error("Initial template should be nil")
	}

	// Set template
	tmpl := template.New("test")
	gen.SetTemplate(tmpl)

	// Test get template
	if gen.GetTemplate() != tmpl {
		t.Error("Template not set correctly")
	}
}

func TestHybridGenerator_SetAndGetBuilder(t *testing.T) {
	reportBuilder := builder.NewMarkdownBuilder()
	logger, loggerErr := log.New(log.Config{})
	if loggerErr != nil {
		t.Fatalf("Failed to create logger: %v", loggerErr)
	}
	gen, genErr := NewHybridGenerator(nil, logger)
	if genErr != nil {
		t.Fatalf("Failed to create hybrid generator: %v", genErr)
	}

	// Test initial state
	if gen.GetBuilder() != nil {
		t.Error("Initial builder should be nil")
	}

	// Set builder
	gen.SetBuilder(reportBuilder)

	// Test get builder
	if gen.GetBuilder() != reportBuilder {
		t.Error("Builder not set correctly")
	}
}
