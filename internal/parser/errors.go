// Package parser provides error types and utilities for parsing OPNsense configuration files.
package parser

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

// ParseError represents an error that occurred during parsing with location information.
type ParseError struct {
	Line    int    // Line number where the error occurred (1-based)
	Column  int    // Column number where the error occurred (1-based)
	Message string // Human-readable error message
}

// NewParseError returns a new ParseError with the given line, column, and error message.
func NewParseError(line, column int, message string) *ParseError {
	return &ParseError{
		Line:    line,
		Column:  column,
		Message: message,
	}
}

// Error implements the error interface for ParseError.
func (e *ParseError) Error() string {
	return fmt.Sprintf("parse error at line %d, column %d: %s", e.Line, e.Column, e.Message)
}

// Is implements error matching for ParseError.
func (e *ParseError) Is(target error) bool {
	if target == nil {
		return false
	}

	// Check if target is the same type
	targetParse, ok := target.(*ParseError)
	if !ok {
		return false
	}

	// If target has zero values, match any ParseError (type-only matching)
	if targetParse.Line == 0 && targetParse.Column == 0 && targetParse.Message == "" {
		return true
	}

	// Otherwise, compare all fields for equality
	return e.Line == targetParse.Line &&
		e.Column == targetParse.Column &&
		e.Message == targetParse.Message
}

// ValidationError represents an error that occurred during validation with path information.
type ValidationError struct {
	Path    string // Element path where the validation error occurred (e.g., "opnsense.system.hostname")
	Message string // Human-readable validation error message
}

// NewValidationError returns a new ValidationError for the given element path and message.
func NewValidationError(path, message string) *ValidationError {
	return &ValidationError{
		Path:    path,
		Message: message,
	}
}

// Error implements the error interface for ValidationError.
func (e *ValidationError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("validation error at %s: %s", e.Path, e.Message)
	}

	return "validation error: " + e.Message
}

// Is implements error matching for ValidationError.
func (e *ValidationError) Is(target error) bool {
	if target == nil {
		return false
	}

	// Check if target is the same type
	targetValidation, ok := target.(*ValidationError)
	if !ok {
		return false
	}

	// If target has zero values, match any ValidationError (type-only matching)
	if targetValidation.Path == "" && targetValidation.Message == "" {
		return true
	}

	// Otherwise, compare all fields for equality
	return e.Path == targetValidation.Path &&
		e.Message == targetValidation.Message
}

// WrapXMLSyntaxError wraps an xml.SyntaxError with location information and marshal context.
// It extracts the line and column information from the xml.SyntaxError and creates a ParseError
// WrapXMLSyntaxError converts an xml.SyntaxError into a ParseError, including the line number and optional element path context.
// If the error is not an xml.SyntaxError, it wraps it as a generic ParseError with the error message. Returns nil if err is nil.
func WrapXMLSyntaxError(err error, elementPath string) error {
	if err == nil {
		return nil
	}

	var syntaxErr *xml.SyntaxError
	if errors.As(err, &syntaxErr) {
		message := syntaxErr.Msg

		// Add element path context if available
		if elementPath != "" {
			message = fmt.Sprintf("%s (in element path: %s)", message, elementPath)
		}

		return &ParseError{
			Line:    syntaxErr.Line,
			Column:  0, // xml.SyntaxError doesn't provide column information
			Message: message,
		}
	}

	// If it's not an xml.SyntaxError, wrap it as a generic ParseError
	return &ParseError{
		Line:    0,
		Column:  0,
		Message: "XML error: " + err.Error(),
	}
}

// BuildElementPath constructs an element path from a slice of element names.
// BuildElementPath returns a dot-separated string representing the XML element path constructed from the provided slice of element names.
func BuildElementPath(elements []string) string {
	return strings.Join(elements, ".")
}

// IsParseError returns true if the provided error is or wraps a ParseError.
func IsParseError(err error) bool {
	var parseErr *ParseError
	return errors.As(err, &parseErr)
}

// IsValidationError returns true if the error is or wraps a ValidationError.
func IsValidationError(err error) bool {
	var validationErr *ValidationError
	return errors.As(err, &validationErr)
}

// GetParseError extracts a ParseError from an error chain.
// GetParseError extracts a ParseError from the error chain, or returns nil if none is found.
func GetParseError(err error) *ParseError {
	var parseErr *ParseError
	if errors.As(err, &parseErr) {
		return parseErr
	}

	return nil
}

// GetValidationError extracts a ValidationError from an error chain.
// GetValidationError extracts a ValidationError from the error chain, or returns nil if none is found.
func GetValidationError(err error) *ValidationError {
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		return validationErr
	}

	return nil
}

// AggregatedValidationError represents a collection of validation errors with context.
type AggregatedValidationError struct {
	Errors []ValidationError // List of validation errors with element paths
}

// NewAggregatedValidationError returns an AggregatedValidationError containing the provided slice of ValidationError instances.
func NewAggregatedValidationError(validationErrors []ValidationError) *AggregatedValidationError {
	return &AggregatedValidationError{
		Errors: validationErrors,
	}
}

// Error implements the error interface for AggregatedValidationError.
func (r *AggregatedValidationError) Error() string {
	if len(r.Errors) == 0 {
		return "no validation errors"
	}

	if len(r.Errors) == 1 {
		return r.Errors[0].Error()
	}

	return fmt.Sprintf("validation failed with %d errors: %s (and %d more)",
		len(r.Errors), r.Errors[0].Message, len(r.Errors)-1)
}

// Is implements error matching for AggregatedValidationError.
func (r *AggregatedValidationError) Is(target error) bool {
	if target == nil {
		return false
	}

	// Check if target is the same type
	targetAgg, ok := target.(*AggregatedValidationError)
	if !ok {
		return false
	}

	// If target has no errors, match any AggregatedValidationError (type-only matching)
	if len(targetAgg.Errors) == 0 {
		return true
	}

	// If target has errors, check if receiver has the same errors
	if len(r.Errors) != len(targetAgg.Errors) {
		return false
	}

	// Compare each error in the slice
	for i, targetErr := range targetAgg.Errors {
		if i >= len(r.Errors) {
			return false
		}

		if !errors.Is(&r.Errors[i], &targetErr) {
			return false
		}
	}

	return true
}

// HasErrors returns true if the report contains any validation errors.
func (r *AggregatedValidationError) HasErrors() bool {
	return len(r.Errors) > 0
}

// WrapXMLSyntaxErrorWithOffset wraps an xml.SyntaxError with enhanced location information using decoder's InputOffset.
// WrapXMLSyntaxErrorWithOffset converts an XML syntax error into a ParseError, including element path and byte offset context when available.
// If the error is not an xml.SyntaxError, it wraps it as a generic ParseError with the current decoder offset. Returns nil if err is nil.
func WrapXMLSyntaxErrorWithOffset(err error, elementPath string, dec *xml.Decoder) error {
	if err == nil {
		return nil
	}

	var syntaxErr *xml.SyntaxError
	if errors.As(err, &syntaxErr) {
		message := syntaxErr.Msg

		// Add element path context if available
		if elementPath != "" {
			message = fmt.Sprintf("%s (in element path: %s)", message, elementPath)
		}

		// Try to get current input offset for more precise location
		offset := dec.InputOffset()
		if offset > 0 {
			message = fmt.Sprintf("%s (at byte offset: %d)", message, offset)
		}

		return &ParseError{
			Line:    syntaxErr.Line,
			Column:  0, // xml.SyntaxError doesn't provide column information
			Message: message,
		}
	}

	// If it's not an xml.SyntaxError, wrap it as a generic ParseError with offset if possible
	offset := dec.InputOffset()

	message := "XML error: " + err.Error()
	if offset > 0 {
		message = fmt.Sprintf("%s (at byte offset: %d)", message, offset)
	}

	return &ParseError{
		Line:    0,
		Column:  0,
		Message: message,
	}
}
