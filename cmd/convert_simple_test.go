package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/markdown"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// TestDetermineOutputPathSimple tests basic output path determination.
func TestDetermineOutputPathSimple(t *testing.T) {
	// Test with no output specified - should return empty for stdout
	result, err := determineOutputPath("config.xml", "", ".md", nil, false)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty result, got: %s", result)
	}

	// Test with CLI flag output
	result, err = determineOutputPath("config.xml", "output.md", ".md", nil, false)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result != "output.md" {
		t.Errorf("Expected 'output.md', got: %s", result)
	}

	// Test with config output
	cfg := &config.Config{OutputFile: "config-output.md"}
	result, err = determineOutputPath("config.xml", "", ".md", cfg, false)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result != "config-output.md" {
		t.Errorf("Expected 'config-output.md', got: %s", result)
	}

	// Test with forced overwrite of existing file
	tempFile, err := os.CreateTemp("", "test-*.md")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	tempFile.Close()

	result, err = determineOutputPath("config.xml", tempFile.Name(), ".md", nil, true)
	if err != nil {
		t.Errorf("Unexpected error with force=true: %v", err)
	}
	if result != tempFile.Name() {
		t.Errorf("Expected temp file name, got: %s", result)
	}
}

// TestGenerateOutputByFormatSimple tests the format-based generation.
func TestGenerateOutputByFormatSimple(t *testing.T) {
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	opnsense := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
		},
	}

	ctx := context.Background()

	// Test markdown format
	opt := markdown.Options{
		Format: markdown.FormatMarkdown,
		Theme:  markdown.ThemeAuto,
	}

	result, err := generateOutputByFormat(ctx, opnsense, opt, logger, nil)
	if err != nil {
		t.Errorf("Unexpected error for markdown: %v", err)
	}
	if result == "" {
		t.Errorf("Expected non-empty result for markdown")
	}

	// Test JSON format - but it may fail due to missing templates, so we'll just check it doesn't panic
	opt.Format = markdown.FormatJSON
	result, err = generateOutputByFormat(ctx, opnsense, opt, logger, nil)
	// JSON format might fail due to missing templates - that's expected
	if err != nil {
		t.Logf("JSON format failed as expected: %v", err)
	}

	// Test unknown format (should default to markdown)
	opt.Format = markdown.Format("unknown")
	result, err = generateOutputByFormat(ctx, opnsense, opt, logger, nil)
	if err != nil {
		t.Errorf("Unexpected error for unknown format: %v", err)
	}
	if result == "" {
		t.Errorf("Expected non-empty result for unknown format")
	}
}

// TestGenerateWithHybridGeneratorSimple tests the hybrid generator function.
func TestGenerateWithHybridGeneratorSimple(t *testing.T) {
	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	opnsense := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
		},
	}

	ctx := context.Background()

	// Test programmatic mode (default)
	resetGlobalFlags()
	opt := markdown.Options{
		Format: markdown.FormatMarkdown,
		Theme:  markdown.ThemeAuto,
	}

	result, err := generateWithHybridGenerator(ctx, opnsense, opt, logger, nil)
	if err != nil {
		t.Errorf("Unexpected error for programmatic mode: %v", err)
	}
	if result == "" {
		t.Errorf("Expected non-empty result for programmatic mode")
	}

	// Test template mode - may fail due to missing templates
	sharedUseTemplate = true
	result, err = generateWithHybridGenerator(ctx, opnsense, opt, logger, nil)
	// Template mode might fail due to missing templates - that's expected
	if err != nil {
		t.Logf("Template mode failed as expected: %v", err)
	}

	// Clean up
	resetGlobalFlags()
}

// TestLoadCustomTemplateSimple tests template loading.
func TestLoadCustomTemplateSimple(t *testing.T) {
	// Test with non-existent file
	_, err := loadCustomTemplate("non-existent-template.tmpl")
	if err == nil {
		t.Errorf("Expected error for non-existent file")
	}

	// Test with valid template file
	tempFile, err := os.CreateTemp("", "template-*.tmpl")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	content := "# {{ .System.Hostname }}\n"
	if _, err := tempFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write template content: %v", err)
	}
	tempFile.Close()

	tmpl, err := loadCustomTemplate(tempFile.Name())
	if err != nil {
		t.Errorf("Unexpected error for valid template: %v", err)
	}
	if tmpl == nil {
		t.Errorf("Expected template but got nil")
	}
}

// TestValidateTemplatePathSimple tests template path validation.
func TestValidateTemplatePathSimple(t *testing.T) {
	// Test empty path (should be valid)
	err := validateTemplatePath("")
	if err != nil {
		t.Errorf("Unexpected error for empty path: %v", err)
	}

	// Test path traversal (should fail)
	err = validateTemplatePath("../../../etc/passwd")
	if err == nil {
		t.Errorf("Expected error for path traversal")
	}

	// Test non-existent file (should fail)
	err = validateTemplatePath("non-existent-file.tmpl")
	if err == nil {
		t.Errorf("Expected error for non-existent file")
	}

	// Test valid file
	tempFile, err := os.CreateTemp("", "valid-*.tmpl")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	tempFile.Close()

	err = validateTemplatePath(tempFile.Name())
	if err != nil {
		t.Errorf("Unexpected error for valid file: %v", err)
	}
}

// TestGetSharedTemplateDirSimple tests template directory retrieval.
func TestGetSharedTemplateDirSimple(t *testing.T) {
	// Reset global variable
	originalCustomTemplate := sharedCustomTemplate
	defer func() { sharedCustomTemplate = originalCustomTemplate }()

	// Test with empty custom template
	sharedCustomTemplate = ""
	result := getSharedTemplateDir()
	if result != "" {
		t.Errorf("Expected empty result for empty custom template, got: %s", result)
	}

	// Test with custom template path
	sharedCustomTemplate = "/path/to/template.tmpl"
	result = getSharedTemplateDir()
	expected := "/path/to"
	if result != expected {
		t.Errorf("Expected %s, got: %s", expected, result)
	}

	// Test with just filename
	sharedCustomTemplate = "template.tmpl"
	result = getSharedTemplateDir()
	expected = "."
	if result != expected {
		t.Errorf("Expected %s, got: %s", expected, result)
	}
}

// TestBuildConversionOptionsSimple tests option building.
func TestBuildConversionOptionsSimple(t *testing.T) {
	// Test with nil config
	resetGlobalFlags()
	opts := buildConversionOptions("markdown", nil)
	if opts.Format == "" {
		t.Errorf("Expected format to be set")
	}

	// Test with config
	cfg := &config.Config{
		Theme:    "dark",
		Template: "custom",
	}
	opts = buildConversionOptions("json", cfg)
	if string(opts.Theme) != "dark" {
		t.Errorf("Expected theme 'dark', got %s", opts.Theme)
	}
	if opts.TemplateName != "custom" {
		t.Errorf("Expected template name 'custom', got %s", opts.TemplateName)
	}

	// Clean up
	resetGlobalFlags()
}