// Package config provides application configuration management.
package config

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// FieldValidationError represents an enhanced configuration validation error with
// detailed context for user-friendly error reporting.
type FieldValidationError struct {
	Field      string   // The configuration field that failed validation
	Message    string   // Description of what went wrong
	Suggestion string   // Helpful suggestion for fixing the error
	LineNumber int      // Line number in config file (0 if unknown)
	Value      string   // The invalid value provided (for context)
	ValidItems []string // Valid options for enum fields
}

func (e *FieldValidationError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message))
	if e.Suggestion != "" {
		sb.WriteString(fmt.Sprintf(" (%s)", e.Suggestion))
	}
	return sb.String()
}

// MultiValidationError represents a collection of validation errors.
type MultiValidationError struct {
	Errors []FieldValidationError
}

func (e *MultiValidationError) Error() string {
	if len(e.Errors) == 0 {
		return "no validation errors"
	}

	var sb strings.Builder
	for i, err := range e.Errors {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(err.Error())
	}
	return sb.String()
}

// Add appends a validation error to the collection.
func (e *MultiValidationError) Add(err FieldValidationError) {
	e.Errors = append(e.Errors, err)
}

// HasErrors returns true if there are any validation errors.
func (e *MultiValidationError) HasErrors() bool {
	return len(e.Errors) > 0
}

// Count returns the number of validation errors.
func (e *MultiValidationError) Count() int {
	return len(e.Errors)
}

// ErrorFormatter provides styled formatting for validation errors.
type ErrorFormatter struct {
	writer io.Writer
	styles ErrorStyles
}

// ErrorStyles contains lipgloss styles for error formatting.
type ErrorStyles struct {
	ErrorLabel     lipgloss.Style
	FieldLabel     lipgloss.Style
	FieldValue     lipgloss.Style
	Suggestion     lipgloss.Style
	ValidOption    lipgloss.Style
	Separator      lipgloss.Style
	LineNumber     lipgloss.Style
	InvalidValue   lipgloss.Style
	Bullet         lipgloss.Style
	Header         lipgloss.Style
	Count          lipgloss.Style
	SectionDivider lipgloss.Style
}

// NewErrorFormatter creates a new ErrorFormatter with default styles.
// It writes to stderr by default.
func NewErrorFormatter() *ErrorFormatter {
	return NewErrorFormatterWithWriter(os.Stderr)
}

// NewErrorFormatterWithWriter creates a new ErrorFormatter writing to the specified writer.
func NewErrorFormatterWithWriter(w io.Writer) *ErrorFormatter {
	return &ErrorFormatter{
		writer: w,
		styles: defaultErrorStyles(),
	}
}

// defaultErrorStyles returns the default error styling configuration.
func defaultErrorStyles() ErrorStyles {
	return ErrorStyles{
		ErrorLabel: lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")). // Red
			Bold(true),
		FieldLabel: lipgloss.NewStyle().
			Foreground(lipgloss.Color("14")). // Cyan
			Bold(true),
		FieldValue: lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")). // Yellow
			Italic(true),
		Suggestion: lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")). // Green
			Italic(true),
		ValidOption: lipgloss.NewStyle().
			Foreground(lipgloss.Color("14")). // Cyan
			Italic(false),
		Separator: lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")), // Gray
		LineNumber: lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")). // Gray
			Italic(true),
		InvalidValue: lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")). // Red
			Bold(true),
		Bullet: lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")), // Gray
		Header: lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")). // Red
			Bold(true).
			Underline(true),
		Count: lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")). // Yellow
			Bold(true),
		SectionDivider: lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")), // Gray
	}
}

// FormatError formats a single validation error with styling.
func (f *ErrorFormatter) FormatError(err *FieldValidationError) {
	// Error header with field name
	fmt.Fprintf(f.writer, "%s %s\n",
		f.styles.ErrorLabel.Render("Error:"),
		f.styles.FieldLabel.Render(err.Field),
	)

	// Error message
	fmt.Fprintf(f.writer, "  %s\n", err.Message)

	// Show invalid value if provided
	if err.Value != "" {
		fmt.Fprintf(f.writer, "  %s %s\n",
			f.styles.Separator.Render("Got:"),
			f.styles.InvalidValue.Render(fmt.Sprintf("'%s'", err.Value)),
		)
	}

	// Show line number if available
	if err.LineNumber > 0 {
		fmt.Fprintf(f.writer, "  %s %s\n",
			f.styles.Separator.Render("Line:"),
			f.styles.LineNumber.Render(strconv.Itoa(err.LineNumber)),
		)
	}

	// Show valid options for enum fields
	if len(err.ValidItems) > 0 {
		fmt.Fprintf(f.writer, "  %s ", f.styles.Separator.Render("Valid options:"))
		validStrs := make([]string, len(err.ValidItems))
		for i, opt := range err.ValidItems {
			validStrs[i] = f.styles.ValidOption.Render(opt)
		}
		fmt.Fprintf(f.writer, "%s\n", strings.Join(validStrs, f.styles.Separator.Render(", ")))
	}

	// Show suggestion if provided
	if err.Suggestion != "" {
		fmt.Fprintf(f.writer, "  %s %s\n",
			f.styles.Bullet.Render("Hint:"),
			f.styles.Suggestion.Render(err.Suggestion),
		)
	}
}

// FormatErrors formats multiple validation errors with styling.
func (f *ErrorFormatter) FormatErrors(errs *MultiValidationError) {
	if !errs.HasErrors() {
		return
	}

	// Header
	fmt.Fprintf(f.writer, "\n%s %s %s\n\n",
		f.styles.Header.Render("Configuration Validation Failed:"),
		f.styles.Count.Render(strconv.Itoa(errs.Count())),
		f.styles.Separator.Render(pluralize(errs.Count(), "error", "errors")),
	)

	// Format each error
	for i, err := range errs.Errors {
		f.FormatError(&err)
		if i < len(errs.Errors)-1 {
			fmt.Fprintf(f.writer, "%s\n",
				f.styles.SectionDivider.Render("  ─────────────────────────────────"))
		}
	}

	fmt.Fprintln(f.writer)
}

// pluralize returns singular or plural form based on count.
func pluralize(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

// ConvertToV2Errors converts legacy ValidationError slice to MultiValidationError.
func ConvertToV2Errors(legacyErrors []ValidationError) *MultiValidationError {
	errs := &MultiValidationError{}
	for _, le := range legacyErrors {
		errs.Add(FieldValidationError{
			Field:   le.Field,
			Message: le.Message,
		})
	}
	return errs
}
