// Package progress provides progress indication for CLI operations.
package progress

import (
	"io"
	"os"
)

// Progress defines the interface for progress indication.
// Implementations can provide different visual representations
// (spinner, bar, percentage, or no-op for quiet mode).
type Progress interface {
	// Start begins progress indication with an initial message.
	Start(message string)

	// Update updates the progress with a percentage (0.0 to 1.0) and message.
	Update(percent float64, message string)

	// Complete marks the progress as successfully completed.
	Complete(message string)

	// Fail marks the progress as failed with an error.
	Fail(err error)
}

// Options configures progress indicator behavior.
type Options struct {
	// Output is the writer for progress output (default: os.Stderr).
	Output io.Writer

	// Width is the width of the progress bar in characters.
	Width int

	// ShowPercentage shows the percentage alongside the progress.
	ShowPercentage bool

	// Enabled controls whether progress is shown at all.
	Enabled bool
}

// Default values for progress options.
const (
	// DefaultProgressWidth is the default width of the progress bar in characters.
	DefaultProgressWidth = 40
)

// DefaultOptions returns the default progress options.
func DefaultOptions() Options {
	return Options{
		Output:         os.Stderr,
		Width:          DefaultProgressWidth,
		ShowPercentage: true,
		Enabled:        true,
	}
}

// New creates a new progress indicator based on the environment and options.
// It automatically selects the best implementation based on:
// - Whether output is a terminal
// - Whether progress is enabled
// - Available terminal capabilities.
func New(opts Options) Progress {
	if !opts.Enabled {
		return NewNoOp()
	}

	// Check if output is a terminal
	if !isTerminal(opts.Output) {
		return NewNoOp()
	}

	// Default to spinner for indeterminate progress
	return NewSpinner(opts)
}

// NewForMultiFile creates a progress indicator suitable for multi-file operations.
// It uses a bar-style indicator that can show overall progress.
func NewForMultiFile(opts Options) Progress {
	if !opts.Enabled {
		return NewNoOp()
	}

	if !isTerminal(opts.Output) {
		return NewNoOp()
	}

	return NewBar(opts)
}

// isTerminal checks if the writer is connected to a terminal.
func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		stat, err := f.Stat()
		if err != nil {
			return false
		}
		return (stat.Mode() & os.ModeCharDevice) != 0
	}
	return false
}
