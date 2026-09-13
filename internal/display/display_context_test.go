package display

import (
	"context"
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

			switch {
			case tt.cancelWhen == "before-render":
				// Deterministic: the context is already cancelled when Display is
				// called, so the first checkpoint must trip. A soft "err != nil"
				// guard here would let a silently-passing nil error through, which
				// is what made the deleted multi-checkpoint test worthless.
				require.ErrorIs(t, err, context.Canceled)
			case tt.expectError && tt.cancelWhen != neverCancel:
				// Genuinely racy: cancellation fires from a goroutine mid-render, so
				// finishing first is a legitimate outcome. Only the error's identity
				// is asserted, not its presence.
				if err != nil {
					require.ErrorIs(t, err, context.Canceled)
				}
			case tt.cancelWhen == neverCancel:
				// Should complete without context cancellation error
				// May have other errors (like renderer errors), but not context.Canceled
				if err != nil {
					assert.NotErrorIs(t, err, context.Canceled)
				}
			}
		})
	}
}
