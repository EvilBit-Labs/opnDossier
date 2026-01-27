package cmd

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
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
	tempFile, err := os.CreateTemp(t.TempDir(), "test-*.md")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	if err := tempFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

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
	opt := converter.Options{
		Format: converter.FormatMarkdown,
		Theme:  converter.ThemeAuto,
	}

	result, err := generateOutputByFormat(ctx, opnsense, opt, logger)
	if err != nil {
		t.Errorf("Unexpected error for markdown: %v", err)
	}
	if result == "" {
		t.Errorf("Expected non-empty result for markdown")
	}

	// Test JSON format - programmatic generation should succeed
	opt.Format = converter.FormatJSON
	jsonResult, err := generateOutputByFormat(ctx, opnsense, opt, logger)
	if err != nil {
		t.Errorf("JSON format should succeed with programmatic generator: %v", err)
	}
	if jsonResult == "" {
		t.Errorf("Expected non-empty result for JSON format")
	}

	// Test unknown format (should return an error)
	opt.Format = converter.Format("unknown")
	_, err = generateOutputByFormat(ctx, opnsense, opt, logger)
	if err == nil {
		t.Errorf("Expected error for unknown format, got nil")
	} else if !errors.Is(err, ErrUnsupportedOutputFormat) {
		t.Errorf("Expected ErrUnsupportedOutputFormat, got: %v", err)
	}
}

// TestGenerateWithProgrammaticGeneratorSimple tests the programmatic generator function.
func TestGenerateWithProgrammaticGeneratorSimple(t *testing.T) {
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
	opt := converter.Options{
		Format: converter.FormatMarkdown,
		Theme:  converter.ThemeAuto,
	}

	result, err := generateWithProgrammaticGenerator(ctx, opnsense, opt, logger)
	if err != nil {
		t.Errorf("Unexpected error for programmatic mode: %v", err)
	}
	if result == "" {
		t.Errorf("Expected non-empty result for programmatic mode")
	}
}

// TestBuildConversionOptionsSimple tests option building.
func TestBuildConversionOptionsSimple(t *testing.T) {
	// Save original values
	origSections := sharedSections
	origWrapWidth := sharedWrapWidth
	origComprehensive := sharedComprehensive
	origIncludeTunables := sharedIncludeTunables

	defer func() {
		sharedSections = origSections
		sharedWrapWidth = origWrapWidth
		sharedComprehensive = origComprehensive
		sharedIncludeTunables = origIncludeTunables
	}()

	// Test with nil config
	sharedSections = nil
	sharedWrapWidth = -1
	sharedComprehensive = false
	sharedIncludeTunables = false

	opts := buildConversionOptions("markdown", nil)
	if opts.Format == "" {
		t.Errorf("Expected format to be set")
	}

	// Test with config
	cfg := &config.Config{
		Theme: "dark",
	}
	opts = buildConversionOptions("json", cfg)
	if string(opts.Theme) != "dark" {
		t.Errorf("Expected theme 'dark', got %s", opts.Theme)
	}
}
