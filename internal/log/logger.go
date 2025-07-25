// Package log provides centralized logging functionality for the opnFocus application.
package log

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/log"
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

// New creates a new logger with the specified configuration.
func New(cfg Config) *Logger {
	// Set default output if not specified
	if cfg.Output == nil {
		cfg.Output = os.Stderr
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
	default:
		// Default to text if unknown format
		logger.SetFormatter(log.TextFormatter)
	}

	return &Logger{Logger: logger}
}

// parseLevel converts a string level to log.Level.
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
