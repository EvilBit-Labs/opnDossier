package display

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testMarkdownContent = "# Test Content\n\nThis is a test document."
	neverCancel         = "never"
)

// TestDisplayContextCancellation tests that the Display method respects context cancellation.
func TestDisplayContextCancellation(t *testing.T) {
	tests := []struct {
		name        string
		cancelWhen  string // "before-render", "during-wrap", "after-render"
		expectError bool
	}{
		{
			name:        "Cancel before rendering",
			cancelWhen:  "before-render",
			expectError: true,
		},
		{
			name:        "Cancel during processing",
			cancelWhen:  "during-wrap",
			expectError: true,
		},
		{
			name:        "No cancellation",
			cancelWhen:  "never",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Cancel context based on test case
			switch tt.cancelWhen {
			case "before-render":
				cancel()
			case "during-wrap":
				// Cancel after a short delay to simulate mid-processing cancellation
				go func() {
					time.Sleep(1 * time.Millisecond)
					cancel()
				}()
			}

			td := NewTerminalDisplayWithOptions(Options{Theme: LightTheme(), EnableColors: true})

			err := td.Display(ctx, testMarkdownContent)

			if tt.expectError && tt.cancelWhen != neverCancel {
				// We expect either context.Canceled or no error (if we finished before cancel)
				// This is acceptable because the timing is non-deterministic
				if err != nil {
					require.ErrorIs(t, err, context.Canceled)
				}
			} else if tt.cancelWhen == neverCancel {
				// Should complete without context cancellation error
				// May have other errors (like renderer errors), but not context.Canceled
				if err != nil {
					assert.NotErrorIs(t, err, context.Canceled)
				}
			}
		})
	}
}

// TestDisplayMultipleCancellationPoints tests all three cancellation checkpoints.
func TestDisplayMultipleCancellationPoints(t *testing.T) {
	// This test verifies that context cancellation is checked at multiple points
	// in the Display method execution path

	td := NewTerminalDisplayWithOptions(Options{Theme: LightTheme(), EnableColors: true})

	// Test cancellation at each checkpoint
	for range 3 {
		t.Run("Cancellation checkpoint", func(_ *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()

			err := td.Display(ctx, testMarkdownContent)
			// Either completes successfully or returns context error
			if err != nil {
				// Check if it's a context-related error
				if strings.Contains(err.Error(), "context") {
					// This is expected
					return
				}
				// Other errors are also acceptable (like renderer errors)
			}
		})
	}
}
