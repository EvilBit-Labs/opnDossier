// Package progress provides progress indication for CLI operations.
package progress

// NoOpProgress is a no-operation progress indicator.
// It implements the Progress interface but does nothing.
// This is used in quiet mode or non-TTY environments.
type NoOpProgress struct{}

// NewNoOp creates a new no-operation progress indicator.
func NewNoOp() *NoOpProgress {
	return &NoOpProgress{}
}

// Start does nothing for no-op progress.
func (n *NoOpProgress) Start(_ string) {}

// Update does nothing for no-op progress.
func (n *NoOpProgress) Update(_ float64, _ string) {}

// Complete does nothing for no-op progress.
func (n *NoOpProgress) Complete(_ string) {}

// Fail does nothing for no-op progress.
func (n *NoOpProgress) Fail(_ error) {}
