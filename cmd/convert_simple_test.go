package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// TestDetermineOutputPathSimple covers destination resolution. Overwrite
// protection moved to confirmOverwrite, so this function no longer touches the
// filesystem and cannot fail.
func TestDetermineOutputPathSimple(t *testing.T) {
	if got := determineOutputPath("", nil); got != "" {
		t.Errorf("no output configured should mean stdout, got: %s", got)
	}

	if got := determineOutputPath("output.md", nil); got != "output.md" {
		t.Errorf("Expected 'output.md', got: %s", got)
	}

	cfg := &config.Config{OutputFile: "config-output.md"}
	if got := determineOutputPath("", cfg); got != "config-output.md" {
		t.Errorf("Expected 'config-output.md', got: %s", got)
	}

	// The CLI flag wins over a configured output_file.
	if got := determineOutputPath("flag.md", cfg); got != "flag.md" {
		t.Errorf("CLI flag should take precedence, got: %s", got)
	}
}

// TestGenerateOutputByFormatSimple tests the format-based generation.
//
// generateOutputByFormat (formerly exercised here directly) had no production
// caller — every real caller in cmd/convert.go resolves the handler via
// converter.DefaultRegistry.Get and generates via
// generateWithProgrammaticGenerator as two separate steps, never through a
// combining wrapper — so it was removed. This test now exercises those two
// steps the same way production does.
func TestGenerateOutputByFormatSimple(t *testing.T) {
	logger, err := logging.New(logging.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-firewall",
		},
	}

	ctx := context.Background()

	// Test markdown format
	opt := converter.Options{
		Format: converter.FormatMarkdown,
		Theme:  converter.ThemeAuto,
	}

	handler, err := converter.DefaultRegistry.Get(string(opt.Format))
	if err != nil {
		t.Errorf("Unexpected error resolving markdown handler: %v", err)
	}
	if handler == nil {
		t.Errorf("Expected non-nil handler for markdown")
	} else if handler.FileExtension() != ".md" {
		t.Errorf("Expected .md extension, got: %s", handler.FileExtension())
	}

	result, err := generateWithProgrammaticGenerator(ctx, device, opt, logger)
	if err != nil {
		t.Errorf("Unexpected error for markdown: %v", err)
	}
	if result == "" {
		t.Errorf("Expected non-empty result for markdown")
	}

	// Test JSON format - programmatic generation should succeed
	opt.Format = converter.FormatJSON

	jsonHandler, err := converter.DefaultRegistry.Get(string(opt.Format))
	if err != nil {
		t.Errorf("Unexpected error resolving JSON handler: %v", err)
	}
	if jsonHandler == nil {
		t.Errorf("Expected non-nil handler for JSON")
	} else if jsonHandler.FileExtension() != ".json" {
		t.Errorf("Expected .json extension, got: %s", jsonHandler.FileExtension())
	}

	jsonResult, err := generateWithProgrammaticGenerator(ctx, device, opt, logger)
	if err != nil {
		t.Errorf("JSON format should succeed with programmatic generator: %v", err)
	}
	if jsonResult == "" {
		t.Errorf("Expected non-empty result for JSON format")
	}

	// Test unknown format (should return an error)
	_, err = converter.DefaultRegistry.Get("unknown")
	if err == nil {
		t.Errorf("Expected error for unknown format, got nil")
	} else if !errors.Is(err, converter.ErrUnsupportedFormat) {
		t.Errorf("Expected converter.ErrUnsupportedFormat, got: %v", err)
	}
}

// TestRunConvert_UnsupportedFormat verifies that runConvert itself — not just
// the registry — surfaces ErrUnsupportedOutputFormat for an unrecognized
// --format value. This is the only remaining production call site that wraps
// the registry's rejection in ErrUnsupportedOutputFormat (the other call site
// was inside the now-deleted generateOutputByFormat), so it is the one place
// left that can prove this cmd-level sentinel still fires.
func TestRunConvert_UnsupportedFormat(t *testing.T) {
	// No t.Parallel: forbidden throughout cmd/ (GOTCHAS 1.1), since the
	// package binds CLI flags to globals.
	fixture := filepath.Join("..", "testdata", "sample.config.1.xml")
	if _, err := os.Stat(fixture); os.IsNotExist(err) {
		t.Fatal("required testdata not available, ensure testdata/ is checked out")
	}

	sharedSnap := captureSharedFlags()
	t.Cleanup(sharedSnap.restore)

	origFormat, origOutput, origForce := format, outputFile, force
	t.Cleanup(func() {
		format, outputFile, force = origFormat, origOutput, origForce
	})

	format = "bogus-format"
	outputFile = ""
	force = true

	testLogger, err := logging.New(logging.Config{Level: "error"})
	require.NoError(t, err)

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())
	//nolint:staticcheck // SA1019: exercising deprecated flat field for backward-compat coverage.
	SetCommandContext(cmd, &CommandContext{
		Config: &config.Config{Format: "bogus-format"},
		Logger: testLogger,
	})

	err = runConvert(cmd, []string{fixture})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedOutputFormat)
}

// TestGenerateWithProgrammaticGeneratorSimple tests the programmatic generator function.
func TestGenerateWithProgrammaticGeneratorSimple(t *testing.T) {
	logger, err := logging.New(logging.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	device := &common.CommonDevice{
		System: common.System{
			Hostname: "test-firewall",
		},
	}

	ctx := context.Background()

	// Test programmatic mode (default)
	opt := converter.Options{
		Format: converter.FormatMarkdown,
		Theme:  converter.ThemeAuto,
	}

	result, err := generateWithProgrammaticGenerator(ctx, device, opt, logger)
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
	//nolint:staticcheck // SA1019: exercising deprecated flat field for backward-compat coverage.
	cfg := &config.Config{
		Theme: "dark",
	}
	opts = buildConversionOptions("json", cfg)
	if string(opts.Theme) != "dark" {
		t.Errorf("Expected theme 'dark', got %s", opts.Theme)
	}
}
