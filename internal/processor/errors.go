package processor

import (
	"errors"
	"fmt"
)

// Error constants for the processor package.
var (
	// ErrConfigurationNil is returned when configuration is nil.
	ErrConfigurationNil = errors.New("configuration cannot be nil")

	// ErrNormalizedConfigUnavailable is returned when normalized configuration is not available.
	ErrNormalizedConfigUnavailable = errors.New("no normalized configuration available for markdown conversion")
)

// UnsupportedFormatError represents an error for unsupported output formats.
type UnsupportedFormatError struct {
	Format string
}

func (e *UnsupportedFormatError) Error() string {
	return "unsupported format: " + e.Format
}

// TestError represents error types for consistent error handling in tests.
type TestError struct {
	GoroutineID int
	Message     string
}

func (e *TestError) Error() string {
	return fmt.Sprintf("goroutine %d: %s", e.GoroutineID, e.Message)
}

// NewTestError creates a new test error with goroutine ID.
func NewTestError(id int, message string) error {
	return &TestError{GoroutineID: id, Message: message}
}

// TestHostnameError represents a hostname mismatch error in tests.
type TestHostnameError struct {
	GoroutineID      int
	ExpectedHostname string
	ActualHostname   string
}

func (e *TestHostnameError) Error() string {
	return fmt.Sprintf("goroutine %d: expected hostname %s, got %s", e.GoroutineID, e.ExpectedHostname, e.ActualHostname)
}
