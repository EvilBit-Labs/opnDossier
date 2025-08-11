package markdown

import (
	"context"
	"errors"
	"testing"
	"text/template"

	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

func TestNewHybridGenerator(t *testing.T) {
	builder := converter.NewMarkdownBuilder()
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Test with nil logger
	gen := NewHybridGenerator(builder, nil)
	if gen == nil {
		t.Fatal("NewHybridGenerator returned nil")
	}
	if gen.builder != builder {
		t.Error("builder not set correctly")
	}

	// Test with logger
	gen = NewHybridGenerator(builder, logger)
	if gen == nil {
		t.Fatal("NewHybridGenerator returned nil")
	}
	if gen.builder != builder {
		t.Error("builder not set correctly")
	}
	if gen.logger != logger {
		t.Error("logger not set correctly")
	}
}

func TestNewHybridGeneratorWithTemplate(t *testing.T) {
	builder := converter.NewMarkdownBuilder()
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	tmpl := template.New("test")

	// Test with nil logger
	gen := NewHybridGeneratorWithTemplate(builder, tmpl, nil)
	if gen == nil {
		t.Fatal("NewHybridGeneratorWithTemplate returned nil")
	}
	if gen.builder != builder {
		t.Error("builder not set correctly")
	}
	if gen.template != tmpl {
		t.Error("template not set correctly")
	}

	// Test with logger
	gen = NewHybridGeneratorWithTemplate(builder, tmpl, logger)
	if gen == nil {
		t.Fatal("NewHybridGeneratorWithTemplate returned nil")
	}
	if gen.builder != builder {
		t.Error("builder not set correctly")
	}
	if gen.template != tmpl {
		t.Error("template not set correctly")
	}
	if gen.logger != logger {
		t.Error("logger not set correctly")
	}
}

func TestHybridGenerator_Generate_Programmatic(t *testing.T) {
	builder := converter.NewMarkdownBuilder()
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	gen := NewHybridGenerator(builder, logger)

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
	if !contains(output, "test-firewall") {
		t.Error("Generated output does not contain hostname")
	}
	if !contains(output, "example.com") {
		t.Error("Generated output does not contain domain")
	}
}

func TestHybridGenerator_Generate_Template(t *testing.T) {
	builder := converter.NewMarkdownBuilder()
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

	gen := NewHybridGeneratorWithTemplate(builder, tmpl, logger)

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
	if !contains(output, "# Test Report") {
		t.Error("Generated output does not contain template title")
	}
	if !contains(output, "Hostname: test-firewall") {
		t.Error("Generated output does not contain hostname from template")
	}
	if !contains(output, "Domain: example.com") {
		t.Error("Generated output does not contain domain from template")
	}
}

func TestHybridGenerator_Generate_Comprehensive(t *testing.T) {
	builder := converter.NewMarkdownBuilder()
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	gen := NewHybridGenerator(builder, logger)

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
	if !contains(output, "test-firewall") {
		t.Error("Generated output does not contain hostname")
	}
	if !contains(output, "example.com") {
		t.Error("Generated output does not contain domain")
	}
}

func TestHybridGenerator_shouldUseTemplate(t *testing.T) {
	builder := converter.NewMarkdownBuilder()
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	gen := NewHybridGenerator(builder, logger)

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

func TestHybridGenerator_Generate_NilData(t *testing.T) {
	builder := converter.NewMarkdownBuilder()
	logger, loggerErr := log.New(log.Config{})
	if loggerErr != nil {
		t.Fatalf("Failed to create logger: %v", loggerErr)
	}
	gen := NewHybridGenerator(builder, logger)

	opts := DefaultOptions()

	// Test with nil data
	_, err := gen.Generate(context.Background(), nil, opts)
	if err == nil {
		t.Error("Expected error for nil data")
	}
	if !errors.Is(err, converter.ErrNilOpnSenseDocument) {
		t.Errorf("Expected ErrNilOpnSenseDocument, got %v", err)
	}
}

func TestHybridGenerator_Generate_NoBuilder(t *testing.T) {
	logger, loggerErr := log.New(log.Config{})
	if loggerErr != nil {
		t.Fatalf("Failed to create logger: %v", loggerErr)
	}
	gen := NewHybridGenerator(nil, logger)

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
	if !contains(err.Error(), "no report builder available") {
		t.Errorf("Expected error about missing builder, got %v", err)
	}
}

func TestHybridGenerator_SetAndGetTemplate(t *testing.T) {
	builder := converter.NewMarkdownBuilder()
	logger, loggerErr := log.New(log.Config{})
	if loggerErr != nil {
		t.Fatalf("Failed to create logger: %v", loggerErr)
	}
	gen := NewHybridGenerator(builder, logger)

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
	builder := converter.NewMarkdownBuilder()
	logger, loggerErr := log.New(log.Config{})
	if loggerErr != nil {
		t.Fatalf("Failed to create logger: %v", loggerErr)
	}
	gen := NewHybridGenerator(nil, logger)

	// Test initial state
	if gen.GetBuilder() != nil {
		t.Error("Initial builder should be nil")
	}

	// Set builder
	gen.SetBuilder(builder)

	// Test get builder
	if gen.GetBuilder() != builder {
		t.Error("Builder not set correctly")
	}
}

// Helper function to check if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || substr == "" || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr)))
}

// Helper function to check if a string contains a substring (case-sensitive).
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
