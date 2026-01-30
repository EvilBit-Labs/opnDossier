// Package config provides application configuration management.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// ValidLogLevels defines the allowed logging levels.
var ValidLogLevels = []string{"debug", "info", "warn", "error"}

// ValidLogFormats defines the allowed logging formats.
var ValidLogFormats = []string{"text", "json"}

// ValidThemes defines the allowed theme values.
var ValidThemes = []string{"light", "dark", "auto", "none", "custom", ""}

// ValidFormats defines the allowed output formats.
var ValidFormats = []string{"markdown", "md", "json", "yaml", "yml", ""}

// ValidExportFormats defines the allowed export formats.
var ValidExportFormats = []string{"markdown", "md", "json", "yaml", "yml", ""}

// ValidEngines defines the allowed generation engines.
var ValidEngines = []string{"programmatic", "template", ""}

// Validator provides comprehensive configuration validation.
type Validator struct {
	errors *MultiValidationError
	config *Config
}

// NewValidator creates a new Validator for the given configuration.
func NewValidator(c *Config) *Validator {
	return &Validator{
		errors: &MultiValidationError{},
		config: c,
	}
}

// Validate performs all validation checks and returns any errors.
func (v *Validator) Validate() *MultiValidationError {
	v.validateFlags()
	v.validateInputFile()
	v.validateOutputFile()
	v.validateTheme()
	v.validateFormat()
	v.validateWrapWidth()
	v.validateEngine()
	v.validateDisplayConfig()
	v.validateExportConfig()
	v.validateLoggingConfig()
	v.validateValidationConfig()

	if v.errors.HasErrors() {
		return v.errors
	}
	return nil
}

// validateFlags validates flag combinations.
func (v *Validator) validateFlags() {
	// Note: Verbose/quiet mutual exclusivity is handled by Cobra flag validation
	// This is kept as a placeholder for potential future flag validations
}

// validateInputFile validates the input file exists if specified.
func (v *Validator) validateInputFile() {
	if v.config.InputFile == "" {
		return
	}

	if _, err := os.Stat(v.config.InputFile); os.IsNotExist(err) {
		v.errors.Add(FieldValidationError{
			Field:      "input_file",
			Message:    "input file does not exist",
			Value:      v.config.InputFile,
			Suggestion: "verify the file path is correct and the file exists",
		})
	} else if err != nil {
		v.errors.Add(FieldValidationError{
			Field:      "input_file",
			Message:    fmt.Sprintf("failed to check input file: %v", err),
			Value:      v.config.InputFile,
			Suggestion: "check file permissions and path accessibility",
		})
	}
}

// validateOutputFile validates the output file directory exists.
func (v *Validator) validateOutputFile() {
	if v.config.OutputFile == "" {
		return
	}

	dir := filepath.Dir(v.config.OutputFile)
	if dir == "." || dir == "" {
		return
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		v.errors.Add(FieldValidationError{
			Field:      "output_file",
			Message:    "output directory does not exist",
			Value:      dir,
			Suggestion: "create the directory with: mkdir -p " + dir,
		})
	} else if err != nil {
		v.errors.Add(FieldValidationError{
			Field:      "output_file",
			Message:    fmt.Sprintf("failed to check output directory: %v", err),
			Value:      dir,
			Suggestion: "check directory permissions",
		})
	}
}

// validateTheme validates the theme setting.
func (v *Validator) validateTheme() {
	if v.config.Theme == "" {
		return
	}

	if !isValidEnum(v.config.Theme, ValidThemes) {
		validOptions := filterEmpty(ValidThemes)
		v.errors.Add(FieldValidationError{
			Field:      "theme",
			Message:    "invalid theme value",
			Value:      v.config.Theme,
			ValidItems: validOptions,
			Suggestion: "use one of the valid themes or leave empty for auto-detection",
		})
	}
}

// validateFormat validates the output format.
func (v *Validator) validateFormat() {
	if v.config.Format == "" {
		return
	}

	if !isValidEnum(v.config.Format, ValidFormats) {
		validOptions := filterEmpty(ValidFormats)
		v.errors.Add(FieldValidationError{
			Field:      "format",
			Message:    "invalid output format",
			Value:      v.config.Format,
			ValidItems: validOptions,
			Suggestion: "markdown/md for Markdown, json for JSON, yaml/yml for YAML",
		})
	}
}

// validateWrapWidth validates the wrap width setting.
func (v *Validator) validateWrapWidth() {
	// -1 = auto-detect, 0 = no wrapping, positive = specific width
	if v.config.WrapWidth < -1 {
		v.errors.Add(FieldValidationError{
			Field:      "wrap",
			Message:    "wrap width must be -1 (auto-detect), 0 (no wrapping), or a positive value",
			Value:      strconv.Itoa(v.config.WrapWidth),
			Suggestion: "use -1 for automatic detection, 0 to disable, or a positive number like 80 or 120",
		})
	}
}

// validateEngine validates the generation engine.
func (v *Validator) validateEngine() {
	// Normalize the engine value
	if v.config.Engine != "" {
		v.config.Engine = strings.ToLower(strings.TrimSpace(v.config.Engine))
	}

	if v.config.Engine == "" {
		return
	}

	if !isValidEnum(v.config.Engine, ValidEngines) {
		validOptions := filterEmpty(ValidEngines)
		v.errors.Add(FieldValidationError{
			Field:      "engine",
			Message:    "invalid generation engine",
			Value:      v.config.Engine,
			ValidItems: validOptions,
			Suggestion: "programmatic is the default and recommended engine",
		})
	}
}

// validateDisplayConfig validates the nested display configuration.
func (v *Validator) validateDisplayConfig() {
	// Validate display width: -1 = auto-detect, positive = specific width
	if v.config.Display.Width < -1 {
		v.errors.Add(FieldValidationError{
			Field:      "display.width",
			Message:    "display width must be -1 (auto-detect) or a positive value",
			Value:      strconv.Itoa(v.config.Display.Width),
			Suggestion: "use -1 for automatic terminal width detection, or a positive number like 80 or 120",
		})
	}
}

// validateExportConfig validates the nested export configuration.
func (v *Validator) validateExportConfig() {
	// Validate export format
	if v.config.Export.Format != "" && !isValidEnum(v.config.Export.Format, ValidExportFormats) {
		validOptions := filterEmpty(ValidExportFormats)
		v.errors.Add(FieldValidationError{
			Field:      "export.format",
			Message:    "invalid export format",
			Value:      v.config.Export.Format,
			ValidItems: validOptions,
			Suggestion: "markdown/md for Markdown, json for JSON, yaml/yml for YAML",
		})
	}

	// Validate export directory only when it's an absolute path.
	// Relative paths are resolved at runtime and may not exist yet during config loading.
	// This is consistent with output_file validation behavior.
	if v.config.Export.Directory != "" && filepath.IsAbs(v.config.Export.Directory) {
		if info, err := os.Stat(v.config.Export.Directory); err != nil {
			if os.IsNotExist(err) {
				v.errors.Add(FieldValidationError{
					Field:      "export.directory",
					Message:    "export directory does not exist",
					Value:      v.config.Export.Directory,
					Suggestion: "create the directory with: mkdir -p " + v.config.Export.Directory,
				})
			} else {
				v.errors.Add(FieldValidationError{
					Field:      "export.directory",
					Message:    fmt.Sprintf("failed to check export directory: %v", err),
					Value:      v.config.Export.Directory,
					Suggestion: "check directory permissions",
				})
			}
		} else if !info.IsDir() {
			v.errors.Add(FieldValidationError{
				Field:      "export.directory",
				Message:    "export path is not a directory",
				Value:      v.config.Export.Directory,
				Suggestion: "specify a directory path, not a file path",
			})
		}
	}
}

// validateLoggingConfig validates the nested logging configuration.
func (v *Validator) validateLoggingConfig() {
	// Validate log level
	if v.config.Logging.Level != "" && !isValidEnum(v.config.Logging.Level, ValidLogLevels) {
		v.errors.Add(FieldValidationError{
			Field:      "logging.level",
			Message:    "invalid log level",
			Value:      v.config.Logging.Level,
			ValidItems: ValidLogLevels,
			Suggestion: "debug for verbose output, info for normal, warn for warnings only, error for errors only",
		})
	}

	// Validate log format
	if v.config.Logging.Format != "" && !isValidEnum(v.config.Logging.Format, ValidLogFormats) {
		v.errors.Add(FieldValidationError{
			Field:      "logging.format",
			Message:    "invalid log format",
			Value:      v.config.Logging.Format,
			ValidItems: ValidLogFormats,
			Suggestion: "text for human-readable output, json for machine-parseable logs",
		})
	}
}

// validateValidationConfig validates the nested validation configuration.
func (v *Validator) validateValidationConfig() {
	// Currently no enum or range validations needed for validation config
	// Both fields (strict, schema_validation) are booleans
	// This method is included for consistency and future extensibility
}

// isValidEnum checks if a value is in the list of valid options (case-insensitive).
func isValidEnum(value string, validOptions []string) bool {
	lower := strings.ToLower(value)
	for _, opt := range validOptions {
		if strings.EqualFold(opt, lower) {
			return true
		}
	}
	return false
}

// filterEmpty removes empty strings from a slice.
func filterEmpty(items []string) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

// ValidateEnumField validates that a field value is in a list of valid options.
// Returns a FieldValidationError if invalid, or nil if valid.
func ValidateEnumField(field, value string, validOptions []string, suggestion string) *FieldValidationError {
	if value == "" {
		return nil
	}

	if !isValidEnum(value, validOptions) {
		return &FieldValidationError{
			Field:      field,
			Message:    "invalid value",
			Value:      value,
			ValidItems: filterEmpty(validOptions),
			Suggestion: suggestion,
		}
	}
	return nil
}

// ValidateRangeField validates that a numeric field is within a valid range.
// Returns a FieldValidationError if invalid, or nil if valid.
func ValidateRangeField(
	field string,
	value, minVal, maxVal int,
	allowSpecial []int,
	suggestion string,
) *FieldValidationError {
	// Check for special allowed values first
	if slices.Contains(allowSpecial, value) {
		return nil
	}

	// Check range
	if value < minVal || value > maxVal {
		rangeDesc := fmt.Sprintf("must be between %d and %d", minVal, maxVal)
		if len(allowSpecial) > 0 {
			specialStrs := make([]string, len(allowSpecial))
			for i, s := range allowSpecial {
				specialStrs[i] = strconv.Itoa(s)
			}
			rangeDesc += fmt.Sprintf(" (or %s)", strings.Join(specialStrs, ", "))
		}

		return &FieldValidationError{
			Field:      field,
			Message:    rangeDesc,
			Value:      strconv.Itoa(value),
			Suggestion: suggestion,
		}
	}
	return nil
}

// ValidateFilePath validates that a file exists at the given path.
// Returns a FieldValidationError if invalid, or nil if valid.
func ValidateFilePath(field, path string, mustExist bool) *FieldValidationError {
	if path == "" {
		return nil
	}

	if mustExist {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return &FieldValidationError{
				Field:      field,
				Message:    "file does not exist",
				Value:      path,
				Suggestion: "verify the file path is correct",
			}
		} else if err != nil {
			return &FieldValidationError{
				Field:      field,
				Message:    fmt.Sprintf("failed to access file: %v", err),
				Value:      path,
				Suggestion: "check file permissions",
			}
		}
	}
	return nil
}

// ValidateDirectoryPath validates that a directory exists or is writable.
// Returns a FieldValidationError if invalid, or nil if valid.
func ValidateDirectoryPath(field, path string, mustExist bool) *FieldValidationError {
	if path == "" {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		if !mustExist {
			return nil // Directory doesn't need to exist
		}
		if os.IsNotExist(err) {
			return &FieldValidationError{
				Field:      field,
				Message:    "directory does not exist",
				Value:      path,
				Suggestion: "create the directory with: mkdir -p " + path,
			}
		}
		return &FieldValidationError{
			Field:      field,
			Message:    fmt.Sprintf("failed to access directory: %v", err),
			Value:      path,
			Suggestion: "check directory permissions",
		}
	}

	if !info.IsDir() {
		return &FieldValidationError{
			Field:      field,
			Message:    "path is not a directory",
			Value:      path,
			Suggestion: "specify a directory path, not a file path",
		}
	}
	return nil
}
