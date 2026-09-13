// Package config provides application configuration management.
package config

import (
	"fmt"
	"strings"
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

// Error returns a formatted string describing the validation error, including field name, message, and optional suggestion.
func (e *FieldValidationError) Error() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "validation error for field '%s': %s", e.Field, e.Message)
	if e.Suggestion != "" {
		fmt.Fprintf(&sb, " (%s)", e.Suggestion)
	}
	return sb.String()
}

// MultiValidationError represents a collection of validation errors.
type MultiValidationError struct {
	Errors []FieldValidationError
}

// Error returns all validation errors joined as a semicolon-separated string.
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
