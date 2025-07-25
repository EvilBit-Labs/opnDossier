// Package log provides centralized logging functionality for the opnFocus application.
package log

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/log"
)

// Error definitions for validation.
var (
	ErrInvalidLogLevel  = errors.New("invalid log level")
	ErrInvalidLogFormat = errors.New("invalid log format")
)

// Logger is the application logger instance.
type Logger struct {
	*log.Logger
}

// Config holds the logger configuration options.
type Config struct {
	// Level is the log level (debug, info, warn, error)
	Level string
	// Format is the output format (text, json)
	Format string
	// Output is the writer to output logs to
	Output io.Writer
	// ReportCaller enables caller reporting
	ReportCaller bool
	// ReportTimestamp enables timestamp reporting
	ReportTimestamp bool
}

// New returns a new Logger instance configured according to the provided Config.
// It validates the log level and format, sets default output to standard error if unspecified, and applies options for caller and timestamp reporting.
// The logger's output format and level are set based on the configuration.
// Returns an error if the log level or format is invalid.
func New(cfg Config) (*Logger, error) {
	// Set default output if not specified
	if cfg.Output == nil {
		cfg.Output = os.Stderr
	}

	// Validate log level
	if err := validateLevel(cfg.Level); err != nil {
		return nil, err
	}

	// Validate format
	if err := validateFormat(cfg.Format); err != nil {
		return nil, err
	}

	// Create logger options
	opts := log.Options{
		ReportCaller:    cfg.ReportCaller,
		ReportTimestamp: cfg.ReportTimestamp,
	}

	// Create the logger
	logger := log.NewWithOptions(cfg.Output, opts)

	// Set log level
	level := parseLevel(cfg.Level)
	logger.SetLevel(level)

	// Set formatter based on format
	switch strings.ToLower(cfg.Format) {
	case "json":
		logger.SetFormatter(log.JSONFormatter)
	case "text", "":
		logger.SetFormatter(log.TextFormatter)
	}

	return &Logger{Logger: logger}, nil
}

// validateLevel returns an error if the provided log level string is not one of "debug", "info", "warn", "warning", "error", or empty.
func validateLevel(level string) error {
	switch strings.ToLower(level) {
	case "debug", "info", "warn", "warning", "error", "":
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrInvalidLogLevel, level)
	}
}

// validateFormat returns an error if the provided log format is not "text", "json", or empty.
func validateFormat(format string) error {
	switch strings.ToLower(format) {
	case "text", "json", "":
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrInvalidLogFormat, format)
	}
}

// parseLevel returns the corresponding log.Level for a given string, defaulting to InfoLevel if the input is unrecognized.
func parseLevel(level string) log.Level {
	switch strings.ToLower(level) {
	case "debug":
		return log.DebugLevel
	case "info", "":
		return log.InfoLevel
	case "warn", "warning":
		return log.WarnLevel
	case "error":
		return log.ErrorLevel
	default:
		return log.InfoLevel
	}
}

// WithContext returns a logger with the provided context.
// Note: charmbracelet/log doesn't have built-in context support,
// but we maintain this method signature for compatibility.
func (l *Logger) WithContext(_ context.Context) *Logger {
	// For now, just return the same logger since charmbracelet/log
	// doesn't have native context support. In the future, we could
	// add context-based functionality if needed.
	return l
}

// WithPrefix returns a logger with the specified prefix.
func (l *Logger) WithPrefix(prefix string) *Logger {
	return &Logger{Logger: l.Logger.WithPrefix(prefix)}
}

// WithFields returns a logger with the specified key-value pairs.
func (l *Logger) WithFields(keyvals ...interface{}) *Logger {
	return &Logger{Logger: l.With(keyvals...)}
}

// Sub creates a sub-logger with the specified subsystem name.
func (l *Logger) Sub(subsystem string) *Logger {
	return &Logger{Logger: l.With("subsystem", subsystem)}
}
