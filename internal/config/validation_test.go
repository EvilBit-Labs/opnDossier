package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertFieldError is a helper to check for a specific field error in validation results.
func assertFieldError(t *testing.T, errs *MultiValidationError, field string, shouldExist bool) {
	t.Helper()
	if errs == nil {
		if shouldExist {
			t.Errorf("expected error for field %s but got nil errors", field)
		}
		return
	}

	found := false
	for _, e := range errs.Errors {
		if e.Field == field {
			found = true
			break
		}
	}

	if shouldExist && !found {
		t.Errorf("expected error for field %s but none found", field)
	}
	if !shouldExist && found {
		t.Errorf("unexpected error for field %s", field)
	}
}

// assertFieldErrorWithValidItems checks for a field error that includes valid items.
func assertFieldErrorWithValidItems(t *testing.T, errs *MultiValidationError, field string) {
	t.Helper()
	require.NotNil(t, errs)
	require.True(t, errs.HasErrors())

	for _, e := range errs.Errors {
		if e.Field == field {
			assert.NotEmpty(t, e.ValidItems, "should include valid options")
			return
		}
	}
	t.Errorf("expected error for field %s but none found", field)
}

func TestValidator_ValidateTheme(t *testing.T) {
	tests := []struct {
		name        string
		theme       string
		expectError bool
	}{
		{"empty theme is valid", "", false},
		{"light theme is valid", "light", false},
		{"dark theme is valid", "dark", false},
		{"auto theme is valid", "auto", false},
		{"none theme is valid", "none", false},
		{"custom theme is valid", "custom", false},
		{"invalid theme", "invalid", true},
		{"random string", "something", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Theme: tt.theme}
			validator := NewValidator(cfg)
			errs := validator.Validate()

			if tt.expectError {
				assertFieldErrorWithValidItems(t, errs, "theme")
			} else {
				assertFieldError(t, errs, "theme", false)
			}
		})
	}
}

func TestValidator_ValidateFormat(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		expectError bool
	}{
		{"empty format is valid", "", false},
		{"markdown format is valid", "markdown", false},
		{"md format is valid", "md", false},
		{"json format is valid", "json", false},
		{"yaml format is valid", "yaml", false},
		{"yml format is valid", "yml", false},
		{"text format is valid", "text", false},
		{"txt format is valid", "txt", false},
		{"html format is valid", "html", false},
		{"htm format is valid", "htm", false},
		{"invalid format", "invalid", true},
		{"xml format is invalid", "xml", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Format: tt.format}
			validator := NewValidator(cfg)
			errs := validator.Validate()

			if tt.expectError {
				assertFieldErrorWithValidItems(t, errs, "format")
			} else {
				assertFieldError(t, errs, "format", false)
			}
		})
	}
}

func TestValidator_ValidateWrapWidth(t *testing.T) {
	tests := []struct {
		name        string
		wrapWidth   int
		expectError bool
	}{
		{"auto-detect (-1) is valid", -1, false},
		{"no wrapping (0) is valid", 0, false},
		{"positive width is valid", 80, false},
		{"large width is valid", 200, false},
		{"negative less than -1 is invalid", -2, true},
		{"very negative is invalid", -100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{WrapWidth: tt.wrapWidth}
			validator := NewValidator(cfg)
			errs := validator.Validate()

			if tt.expectError {
				require.NotNil(t, errs)
				assertFieldError(t, errs, "wrap", true)
			} else {
				assertFieldError(t, errs, "wrap", false)
			}
		})
	}
}

func TestValidator_ValidateDisplayWidth(t *testing.T) {
	tests := []struct {
		name        string
		width       int
		expectError bool
	}{
		{"auto-detect (-1) is valid", -1, false},
		{"zero is valid", 0, false},
		{"positive width is valid", 120, false},
		{"negative less than -1 is invalid", -2, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Display: DisplayConfig{Width: tt.width},
			}
			validator := NewValidator(cfg)
			errs := validator.Validate()

			assertFieldError(t, errs, "display.width", tt.expectError)
		})
	}
}

func TestValidator_ValidateLoggingLevel(t *testing.T) {
	tests := []struct {
		name        string
		level       string
		expectError bool
	}{
		{"empty level uses default", "", false},
		{"debug level is valid", "debug", false},
		{"info level is valid", "info", false},
		{"warn level is valid", "warn", false},
		{"error level is valid", "error", false},
		{"invalid level", "verbose", true},
		{"trace is invalid", "trace", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Logging: LoggingConfig{Level: tt.level},
			}
			validator := NewValidator(cfg)
			errs := validator.Validate()

			if !tt.expectError {
				assertFieldError(t, errs, "logging.level", false)
				return
			}

			require.NotNil(t, errs)
			require.True(t, errs.HasErrors())
			// Verify valid items are present
			for _, e := range errs.Errors {
				if e.Field != "logging.level" {
					continue
				}
				assert.Contains(t, e.ValidItems, "debug")
				assert.Contains(t, e.ValidItems, "info")
				assert.Contains(t, e.ValidItems, "warn")
				assert.Contains(t, e.ValidItems, "error")
				return
			}
			t.Error("expected logging.level error but none found")
		})
	}
}

func TestValidator_ValidateLoggingFormat(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		expectError bool
	}{
		{"empty format uses default", "", false},
		{"text format is valid", "text", false},
		{"json format is valid", "json", false},
		{"invalid format", "xml", true},
		{"invalid format verbose", "verbose", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Logging: LoggingConfig{Format: tt.format},
			}
			validator := NewValidator(cfg)
			errs := validator.Validate()

			if tt.expectError {
				require.NotNil(t, errs)
				require.True(t, errs.HasErrors())
				// Verify valid items are present
				for _, e := range errs.Errors {
					if e.Field == "logging.format" {
						assert.Contains(t, e.ValidItems, "text")
						assert.Contains(t, e.ValidItems, "json")
						return
					}
				}
				t.Error("expected logging.format error but none found")
			} else {
				assertFieldError(t, errs, "logging.format", false)
			}
		})
	}
}

func TestValidator_ValidateExportFormat(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		expectError bool
	}{
		{"empty format uses default", "", false},
		{"markdown format is valid", "markdown", false},
		{"json format is valid", "json", false},
		{"yaml format is valid", "yaml", false},
		{"invalid format", "xml", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Export: ExportConfig{Format: tt.format},
			}
			validator := NewValidator(cfg)
			errs := validator.Validate()

			assertFieldError(t, errs, "export.format", tt.expectError)
		})
	}
}

func TestValidator_ValidateInputFile(t *testing.T) {
	// Create a temporary file for testing
	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "existing.xml")
	err := os.WriteFile(existingFile, []byte("<test/>"), 0o600)
	require.NoError(t, err)

	tests := []struct {
		name        string
		inputFile   string
		expectError bool
	}{
		{"empty input file is valid", "", false},
		{"existing file is valid", existingFile, false},
		{"non-existent file", "/nonexistent/file.xml", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{InputFile: tt.inputFile}
			validator := NewValidator(cfg)
			errs := validator.Validate()

			assertFieldError(t, errs, "input_file", tt.expectError)
		})
	}
}

func TestValidator_ValidateOutputFile(t *testing.T) {
	tmpDir := t.TempDir()
	validOutputFile := filepath.Join(tmpDir, "output.md")

	tests := []struct {
		name        string
		outputFile  string
		expectError bool
	}{
		{"empty output file is valid", "", false},
		{"valid output directory", validOutputFile, false},
		{"non-existent output directory", "/nonexistent/dir/output.md", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{OutputFile: tt.outputFile}
			validator := NewValidator(cfg)
			errs := validator.Validate()

			assertFieldError(t, errs, "output_file", tt.expectError)
		})
	}
}

func TestValidator_ValidateExportDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file (not directory) for testing
	notADir := filepath.Join(tmpDir, "notadir.txt")
	err := os.WriteFile(notADir, []byte("test"), 0o600)
	require.NoError(t, err)

	// Create a cross-platform absolute path that doesn't exist
	// Using tmpDir as base ensures it's absolute on all platforms
	nonExistentAbsDir := filepath.Join(tmpDir, "nonexistent", "subdir")

	tests := []struct {
		name        string
		directory   string
		expectError bool
	}{
		{"empty directory is valid", "", false},
		{"existing directory is valid", tmpDir, false},
		{"relative directory skipped", "./output", false}, // Relative paths are not validated
		{"non-existent absolute directory", nonExistentAbsDir, true},
		{"path is a file not directory", notADir, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Export: ExportConfig{Directory: tt.directory},
			}
			validator := NewValidator(cfg)
			errs := validator.Validate()

			assertFieldError(t, errs, "export.directory", tt.expectError)
		})
	}
}

func TestValidator_MultipleErrors(t *testing.T) {
	cfg := &Config{
		Theme:     "invalid_theme",
		Format:    "invalid_format",
		WrapWidth: -5,
		Logging:   LoggingConfig{Level: "invalid_level"},
	}

	validator := NewValidator(cfg)
	errs := validator.Validate()

	require.NotNil(t, errs)
	require.True(t, errs.HasErrors())
	assert.GreaterOrEqual(t, errs.Count(), 4, "should have at least 4 errors")

	// Check that all expected fields have errors
	fields := make(map[string]bool)
	for _, e := range errs.Errors {
		fields[e.Field] = true
	}

	assert.True(t, fields["theme"], "should have theme error")
	assert.True(t, fields["format"], "should have format error")
	assert.True(t, fields["wrap"], "should have wrap error")
	assert.True(t, fields["logging.level"], "should have logging.level error")
}

func TestIsValidEnum(t *testing.T) {
	validOptions := []string{"option1", "option2", "OPTION3"}

	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"exact match", "option1", true},
		{"case insensitive", "OPTION1", true},
		{"case insensitive uppercase", "option3", true},
		{"not in list", "option4", false},
		{"empty string not in list", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidEnum(tt.value, validOptions)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterEmpty(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{"no empty strings", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"with empty strings", []string{"a", "", "b", "", "c"}, []string{"a", "b", "c"}},
		{"all empty strings", []string{"", "", ""}, []string{}},
		{"empty slice", []string{}, []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterEmpty(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertToLegacyError(t *testing.T) {
	t.Run("nil errors returns nil", func(t *testing.T) {
		result := convertToLegacyError(nil)
		assert.NoError(t, result)
	})

	t.Run("empty errors returns nil", func(t *testing.T) {
		errs := &MultiValidationError{}
		result := convertToLegacyError(errs)
		assert.NoError(t, result)
	})

	t.Run("converts errors to legacy format", func(t *testing.T) {
		errs := &MultiValidationError{
			Errors: []FieldValidationError{
				{Field: "field1", Message: "error1"},
				{Field: "field2", Message: "error2"},
			},
		}
		result := convertToLegacyError(errs)
		require.Error(t, result)
		assert.Contains(t, result.Error(), "field1")
		assert.Contains(t, result.Error(), "error1")
		assert.Contains(t, result.Error(), "field2")
		assert.Contains(t, result.Error(), "error2")
	})
}
