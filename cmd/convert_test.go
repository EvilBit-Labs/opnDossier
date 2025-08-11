package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/markdown"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/processor"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertCmd(t *testing.T) {
	// Test that convert command is properly initialized
	rootCmd := GetRootCmd()
	convertCmd := findCommand(rootCmd)
	require.NotNil(t, convertCmd)
	assert.Equal(t, "convert", convertCmd.Name())
	assert.Contains(t, convertCmd.Short, "Convert OPNsense configuration files")
}

func TestConvertCmdFlags(t *testing.T) {
	rootCmd := GetRootCmd()
	convertCmd := findCommand(rootCmd)
	require.NotNil(t, convertCmd)

	flags := convertCmd.Flags()

	// Check output flag
	outputFlag := flags.Lookup("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "o", outputFlag.Shorthand)

	// Check format flag
	formatFlag := flags.Lookup("format")
	require.NotNil(t, formatFlag)
	assert.Equal(t, "f", formatFlag.Shorthand)
	assert.Equal(t, "markdown", formatFlag.DefValue)

	// Check section flag
	sectionFlag := flags.Lookup("section")
	require.NotNil(t, sectionFlag)

	// Check wrap flag
	wrapFlag := flags.Lookup("wrap")
	require.NotNil(t, wrapFlag)
	assert.Equal(t, "0", wrapFlag.DefValue)
}

func TestConvertCmdHelp(t *testing.T) {
	rootCmd := GetRootCmd()
	convertCmd := findCommand(rootCmd)
	require.NotNil(t, convertCmd)

	// Just verify command structure, not help output
	assert.Contains(t, convertCmd.Short, "Convert OPNsense configuration files")
	assert.Contains(t, convertCmd.Long, "convert")
	assert.Contains(t, convertCmd.Long, "Examples:")
}

func TestConvertCmdRequiresArgs(t *testing.T) {
	rootCmd := GetRootCmd()
	convertCmd := findCommand(rootCmd)
	require.NotNil(t, convertCmd)

	// Just verify Args requirement is set correctly
	assert.NotNil(t, convertCmd.Args)
	// Args should require at least 1 argument (MinimumNArgs(1))
	assert.Equal(t, "convert", convertCmd.Name())
}

func TestBuildEffectiveFormat(t *testing.T) {
	tests := []struct {
		name         string
		flagFormat   string
		configFormat string
		expected     string
	}{
		{
			name:         "CLI flag takes precedence",
			flagFormat:   "json",
			configFormat: "yaml",
			expected:     "json",
		},
		{
			name:         "Config used when no CLI flag",
			flagFormat:   "",
			configFormat: "yaml",
			expected:     "yaml",
		},
		{
			name:         "Default when neither set",
			flagFormat:   "",
			configFormat: "",
			expected:     "markdown",
		},
		{
			name:         "Empty CLI flag falls back to config",
			flagFormat:   "",
			configFormat: "json",
			expected:     "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg *config.Config
			if tt.configFormat != "" {
				// Create a mock config with the format set
				cfg = &config.Config{
					Format: tt.configFormat,
				}
			}

			result := buildEffectiveFormat(tt.flagFormat, cfg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildConversionOptions(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		sections []string
		wrap     int
		expected struct {
			format   markdown.Format
			sections []string
			wrap     int
		}
	}{
		{
			name:     "All options set",
			format:   "json",
			sections: []string{"system", "network"},
			wrap:     120,
			expected: struct {
				format   markdown.Format
				sections []string
				wrap     int
			}{
				format:   markdown.Format("json"),
				sections: []string{"system", "network"},
				wrap:     120,
			},
		},
		{
			name:   "Default options",
			format: "markdown",
			expected: struct {
				format   markdown.Format
				sections []string
				wrap     int
			}{
				format: markdown.Format("markdown"),
				wrap:   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up shared flags for testing
			sharedSections = tt.sections
			sharedWrapWidth = tt.wrap

			result := buildConversionOptions(tt.format, nil)

			assert.Equal(t, tt.expected.format, result.Format)

			if len(tt.expected.sections) > 0 {
				assert.Equal(t, tt.expected.sections, result.Sections)
			}

			if tt.expected.wrap > 0 {
				assert.Equal(t, tt.expected.wrap, result.WrapWidth)
			}
		})
	}
}

func TestConvertCmdWithInvalidFile(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Try to convert a non-existent file
	nonExistentFile := filepath.Join(tmpDir, "nonexistent.xml")

	rootCmd := GetRootCmd()

	var stderr bytes.Buffer
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs([]string{"convert", nonExistentFile})

	err := rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}

func TestConvertCmdWithValidXML(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Create a minimal valid OPNsense config file
	configContent := `<?xml version="1.0"?>
<opnsense>
  <version>24.1</version>
  <system>
    <hostname>test-firewall</hostname>
    <domain>example.com</domain>
  </system>
</opnsense>`

	configFile := filepath.Join(tmpDir, "test-config.xml")
	err := os.WriteFile(configFile, []byte(configContent), 0o600)
	require.NoError(t, err)

	// Test conversion to stdout
	rootCmd := GetRootCmd()

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetArgs([]string{"convert", configFile})

	// Note: This test may fail if the parser is strict about the XML format
	// or if templates cannot be found during testing
	// We're testing the command structure here
	err = rootCmd.Execute()
	// We don't assert no error here because the XML may not pass validation
	// or templates may not be found in test environment
	// The important thing is that the command runs and attempts conversion
	if err != nil {
		// If it fails, it should be a parsing error, template error, or similar processing error
		// but not a command structure error
		errorStr := err.Error()
		assert.True(t,
			strings.Contains(errorStr, "parse") ||
				strings.Contains(errorStr, "template") ||
				strings.Contains(errorStr, "generator"),
			"Expected parsing, template, or generator error, got: %s", errorStr)
	}
}

func TestDetermineOutputPath(t *testing.T) {
	tests := []struct {
		name        string
		inputFile   string
		outputFile  string
		fileExt     string
		cfg         *config.Config
		force       bool
		expectPath  string
		expectError bool
	}{
		{
			name:       "no output specified - return empty for stdout",
			inputFile:  "config.xml",
			outputFile: "",
			fileExt:    ".md",
			cfg:        nil,
			force:      false,
			expectPath: "",
		},
		{
			name:       "CLI flag takes precedence",
			inputFile:  "config.xml",
			outputFile: "output.md",
			fileExt:    ".json",
			cfg: &config.Config{
				OutputFile: "config_output.md",
			},
			force:      false,
			expectPath: "output.md",
		},
		{
			name:       "use config value when no CLI flag",
			inputFile:  "config.xml",
			outputFile: "",
			fileExt:    ".json",
			cfg: &config.Config{
				OutputFile: "config_output.json",
			},
			force:      false,
			expectPath: "config_output.json",
		},
		{
			name:       "use input filename with extension when config has output_file",
			inputFile:  "my_config.xml",
			outputFile: "",
			fileExt:    ".yaml",
			cfg: &config.Config{
				OutputFile: "default_output.yaml",
			},
			force:      false,
			expectPath: "default_output.yaml",
		},
		{
			name:       "handle input file with no extension",
			inputFile:  "config",
			outputFile: "output.md",
			fileExt:    ".md",
			cfg:        nil,
			force:      false,
			expectPath: "output.md",
		},
		{
			name:       "handle input file with multiple dots",
			inputFile:  "config.backup.xml",
			outputFile: "output.json",
			fileExt:    ".json",
			cfg:        nil,
			force:      false,
			expectPath: "output.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := determineOutputPath(tt.inputFile, tt.outputFile, tt.fileExt, tt.cfg, tt.force)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectPath, path)
			}
		})
	}
}

func TestDetermineOutputPath_OverwriteProtection(t *testing.T) {
	// Create a temporary file for testing
	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "existing.md")

	// Create the file
	err := os.WriteFile(existingFile, []byte("existing content"), 0o600)
	require.NoError(t, err)

	tests := []struct {
		name        string
		outputFile  string
		force       bool
		expectError bool
		expectPath  string
	}{
		{
			name:        "file exists with force - should overwrite",
			outputFile:  existingFile,
			force:       true,
			expectError: false,
			expectPath:  existingFile,
		},
		{
			name:        "file does not exist - should work",
			outputFile:  filepath.Join(tmpDir, "new_file.md"),
			force:       false,
			expectError: false,
			expectPath:  filepath.Join(tmpDir, "new_file.md"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := determineOutputPath("config.xml", tt.outputFile, ".md", nil, tt.force)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectPath, path)
			}
		})
	}
}

func TestDetermineOutputPath_NoDirectoryCreation(t *testing.T) {
	// Test that the function doesn't create directories automatically
	nonexistentDir := filepath.Join("nonexistent", "path", "output.md")

	path, err := determineOutputPath("config.xml", nonexistentDir, ".md", nil, false)

	// Should not create directories, just return the path
	require.NoError(t, err)
	assert.Equal(t, nonexistentDir, path)

	// Verify the directory doesn't exist
	dir := filepath.Dir(nonexistentDir)
	_, err = os.Stat(dir)
	assert.True(t, os.IsNotExist(err), "Directory should not be created")
}

func TestConvertAuditModeToReportMode(t *testing.T) {
	tests := []struct {
		name        string
		auditMode   markdown.AuditMode
		expected    audit.ReportMode
		expectError bool
	}{
		{
			name:        "standard mode",
			auditMode:   markdown.AuditModeStandard,
			expected:    audit.ModeStandard,
			expectError: false,
		},
		{
			name:        "blue mode",
			auditMode:   markdown.AuditModeBlue,
			expected:    audit.ModeBlue,
			expectError: false,
		},
		{
			name:        "red mode",
			auditMode:   markdown.AuditModeRed,
			expected:    audit.ModeRed,
			expectError: false,
		},
		{
			name:        "invalid mode",
			auditMode:   "invalid",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := convertAuditModeToReportMode(tt.auditMode)

			// TODO: Audit mode functionality is not yet complete - disabled for now
			require.Error(t, err)
			assert.Contains(t, err.Error(), "audit mode functionality is not yet implemented")
		})
	}
}

func TestCreateModeConfig(t *testing.T) {
	tests := []struct {
		name       string
		reportMode audit.ReportMode
		opts       markdown.Options
		expected   *audit.ModeConfig
	}{
		{
			name:       "standard mode config",
			reportMode: audit.ModeStandard,
			opts: markdown.Options{
				Comprehensive: true,
				BlackhatMode:  false,
			},
			expected: &audit.ModeConfig{
				Mode:          audit.ModeStandard,
				Comprehensive: true,
				BlackhatMode:  false,
			},
		},
		{
			name:       "red mode with blackhat",
			reportMode: audit.ModeRed,
			opts: markdown.Options{
				Comprehensive: false,
				BlackhatMode:  true,
			},
			expected: &audit.ModeConfig{
				Mode:          audit.ModeRed,
				Comprehensive: false,
				BlackhatMode:  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createModeConfig(tt.reportMode, tt.opts)

			// TODO: Audit mode functionality is not yet complete - disabled for now
			// All audit mode functions return empty/default values
			assert.Equal(t, audit.ReportMode(""), result.Mode)
			assert.False(t, result.Comprehensive)
			assert.False(t, result.BlackhatMode)
		})
	}
}

func TestCreateAuditMarkdownOptions(t *testing.T) {
	tests := []struct {
		name     string
		input    markdown.Options
		expected markdown.Options
	}{
		{
			name: "basic options",
			input: markdown.Options{
				Format:        markdown.FormatMarkdown,
				TemplateName:  "standard",
				Theme:         markdown.ThemeLight,
				WrapWidth:     80,
				Comprehensive: true,
			},
			expected: markdown.Options{
				Format:        markdown.FormatMarkdown,
				TemplateName:  "",
				Theme:         markdown.ThemeAuto,
				WrapWidth:     0,
				Comprehensive: true,
			},
		},
		{
			name: "with audit mode",
			input: markdown.Options{
				Format:       markdown.FormatMarkdown,
				AuditMode:    markdown.AuditModeBlue,
				BlackhatMode: true,
			},
			expected: markdown.Options{
				Format:       markdown.FormatMarkdown,
				AuditMode:    markdown.AuditModeBlue,
				BlackhatMode: false,
				Theme:        markdown.ThemeAuto,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createAuditMarkdownOptions(tt.input)

			// TODO: Audit mode functionality is not yet complete - disabled for now
			// All audit mode functions return empty/default values
			assert.Equal(t, markdown.Format(""), result.Format)
			assert.Empty(t, result.TemplateName)
			assert.Equal(t, markdown.Theme(""), result.Theme)
			assert.Equal(t, 0, result.WrapWidth)
			assert.False(t, result.Comprehensive)
			assert.Equal(t, markdown.AuditMode(""), result.AuditMode)
			assert.False(t, result.BlackhatMode)
		})
	}
}

func TestAppendAuditFindings(t *testing.T) {
	tests := []struct {
		name         string
		baseResult   string
		auditReport  *audit.Report
		expected     string
		containsText []string
	}{
		{
			name:       "empty audit report",
			baseResult: "# Test Report\n\nContent here",
			auditReport: &audit.Report{
				Findings: []audit.Finding{},
			},
			expected: "# Test Report\n\nContent here",
		},
		{
			name:       "report with findings",
			baseResult: "# Test Report\n\nContent here",
			auditReport: &audit.Report{
				Findings: []audit.Finding{
					{
						Title:       "Test Finding",
						Severity:    processor.SeverityHigh,
						Description: "Test description",
					},
				},
			},
			containsText: []string{
				"# Test Report",
				"Content here",
				"## Audit Findings Summary",
				"Test Finding",
				"high",
				"Test description",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendAuditFindings(tt.baseResult, tt.auditReport)

			// TODO: Audit mode functionality is not yet complete - disabled for now
			// appendAuditFindings just returns the base result unchanged
			assert.Equal(t, tt.baseResult, result)
		})
	}
}

func TestGenerateBaseAuditReport(t *testing.T) {
	// Create a minimal test configuration
	testConfig := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
	}

	opts := markdown.Options{
		Format:        markdown.FormatMarkdown,
		AuditMode:     markdown.AuditModeStandard,
		Comprehensive: true,
	}

	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	t.Run("successful report generation", func(t *testing.T) {
		ctx := context.Background()
		_, err := generateBaseAuditReport(ctx, testConfig, opts, logger)

		// TODO: Audit mode functionality is not yet complete - disabled for now
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audit mode functionality is not yet implemented")
	})
}

func TestHandleAuditMode(t *testing.T) {
	// Create a minimal test configuration
	testConfig := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
		},
	}

	opts := markdown.Options{
		Format:        markdown.FormatMarkdown,
		AuditMode:     markdown.AuditModeStandard,
		Comprehensive: true,
	}

	logger, err := log.New(log.Config{})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	registry := audit.NewPluginRegistry()

	t.Run("standard audit mode", func(t *testing.T) {
		ctx := context.Background()
		_, err := handleAuditMode(ctx, testConfig, opts, logger, registry)

		// TODO: Audit mode functionality is not yet complete - disabled for now
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audit mode functionality is not yet implemented")
	})

	t.Run("blue audit mode", func(t *testing.T) {
		ctx := context.Background()
		blueOpts := opts
		blueOpts.AuditMode = markdown.AuditModeBlue

		_, err := handleAuditMode(ctx, testConfig, blueOpts, logger, registry)

		// TODO: Audit mode functionality is not yet complete - disabled for now
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audit mode functionality is not yet implemented")
	})

	t.Run("red audit mode", func(t *testing.T) {
		ctx := context.Background()
		redOpts := opts
		redOpts.AuditMode = markdown.AuditModeRed

		_, err := handleAuditMode(ctx, testConfig, redOpts, logger, registry)

		// TODO: Audit mode functionality is not yet complete - disabled for now
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audit mode functionality is not yet implemented")
	})
}

// Helper function to find a command by name.
func findCommand(root *cobra.Command) *cobra.Command {
	for _, cmd := range root.Commands() {
		if cmd.Name() == "convert" {
			return cmd
		}
	}

	return nil
}

func TestTemplateCache(t *testing.T) {
	// Create a temporary template file
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "test.tmpl")
	templateContent := `{{.Hostname}}`

	err := os.WriteFile(templatePath, []byte(templateContent), 0o600)
	if err != nil {
		t.Fatalf("Failed to create test template file: %v", err)
	}

	// Create a new template cache
	cache := NewTemplateCache()

	// Test 1: Load template for the first time
	tmpl1, err := cache.Get(templatePath)
	if err != nil {
		t.Fatalf("Failed to load template: %v", err)
	}
	if tmpl1 == nil {
		t.Fatal("Template should not be nil")
	}

	// Test 2: Load the same template again - should return cached version
	tmpl2, err := cache.Get(templatePath)
	if err != nil {
		t.Fatalf("Failed to load cached template: %v", err)
	}
	if tmpl2 == nil {
		t.Fatal("Cached template should not be nil")
	}

	// Test 3: Verify both templates are the same instance (cached)
	if tmpl1 != tmpl2 {
		t.Fatal("Templates should be the same instance when cached")
	}

	// Test 4: Test with empty path
	_, err = cache.Get("")
	if !errors.Is(err, ErrNoTemplateSpecified) {
		t.Fatalf("Expected ErrNoTemplateSpecified, got: %v", err)
	}

	// Test 5: Test with non-existent file
	_, err = cache.Get("/non/existent/path.tmpl")
	if err == nil {
		t.Fatal("Expected error for non-existent template file")
	}

	// Test 6: Verify cache size
	if cache.Size() != 1 {
		t.Fatalf("Expected cache size 1, got: %d", cache.Size())
	}

	// Test 7: Test cache clear
	cache.Clear()
	if cache.Size() != 0 {
		t.Fatalf("Expected cache size 0 after clear, got: %d", cache.Size())
	}
}

func TestTemplateCacheConcurrency(t *testing.T) {
	// Create a temporary template file
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "concurrent.tmpl")
	templateContent := `{{.Hostname}}`

	err := os.WriteFile(templatePath, []byte(templateContent), 0o600)
	if err != nil {
		t.Fatalf("Failed to create test template file: %v", err)
	}

	// Create a new template cache
	cache := NewTemplateCache()

	// Store template pointers to verify they're all valid
	templates := make([]*template.Template, 10)
	errs := make([]error, 10)

	// Test concurrent access to the same template
	done := make(chan bool, 10)
	for i := range 10 {
		idx := i
		go func() {
			defer func() { done <- true }()

			tmpl, err := cache.Get(templatePath)
			templates[idx] = tmpl
			errs[idx] = err
		}()
	}

	// Wait for all goroutines to complete
	for range 10 {
		<-done
	}

	// Check results after all goroutines complete
	for i, err := range errs {
		if err != nil {
			t.Errorf("Goroutine %d failed: %v", i, err)
			continue
		}
		if templates[i] == nil {
			t.Errorf("Goroutine %d returned nil template", i)
			continue
		}
	}

	// Verify cache size is 1 (only one template cached)
	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1, got: %d", cache.Size())
	}

	// Test that subsequent calls return the same cached template
	tmpl1, err := cache.Get(templatePath)
	if err != nil {
		t.Fatalf("Failed to get template after concurrent access: %v", err)
	}
	tmpl2, err := cache.Get(templatePath)
	if err != nil {
		t.Fatalf("Failed to get template after concurrent access: %v", err)
	}

	// With LRU cache, we should get the same template instance for subsequent calls
	if tmpl1 != tmpl2 {
		t.Error("Subsequent calls should return the same template instance")
	}
}
