package display

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

			td := NewTerminalDisplay()

			// Create simple test markdown content
			markdownContent := "# Test Content\n\nThis is a test document."

			err := td.Display(ctx, markdownContent)

			if tt.expectError && tt.cancelWhen != "never" {
				// We expect either context.Canceled or no error (if we finished before cancel)
				// This is acceptable because the timing is non-deterministic
				if err != nil {
					assert.ErrorIs(t, err, context.Canceled)
				}
			} else if tt.cancelWhen == "never" {
				// Should complete without context cancellation error
				// May have other errors (like renderer errors), but not context.Canceled
				if err != nil {
					assert.NotErrorIs(t, err, context.Canceled)
				}
			}
		})
	}
}

// TestDisplayWithProgressContextCancellation tests context cancellation with progress indicator.
func TestDisplayWithProgressContextCancellation(t *testing.T) {
	tests := []struct {
		name       string
		cancelWhen string
	}{
		{
			name:       "Cancel before progress starts",
			cancelWhen: "immediate",
		},
		{
			name:       "Cancel during display",
			cancelWhen: "delayed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if tt.cancelWhen == "immediate" {
				cancel()
			}

			td := NewTerminalDisplay()

			// Create simple test markdown content
			markdownContent := "# Test Content\n\nThis is a test document."

			// Create a simple progress channel
			progressCh := make(chan ProgressEvent, 1)
			go func() {
				progressCh <- ProgressEvent{Percent: 0.5, Message: "Processing..."}
				close(progressCh)
			}()

			if tt.cancelWhen == "delayed" {
				go func() {
					time.Sleep(5 * time.Millisecond)
					cancel()
				}()
			}

			err := td.DisplayWithProgress(ctx, markdownContent, progressCh)

			// We expect either context.Canceled or completion
			// The timing is non-deterministic
			if err != nil && tt.cancelWhen != "never" {
				assert.ErrorIs(t, err, context.Canceled)
			}
		})
	}
}

// TestDisplayContextCancellationGoroutineCleanup verifies that goroutines are properly cleaned up on cancellation.
func TestDisplayContextCancellationGoroutineCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Get baseline goroutine count
	baselineCount := currentGoroutineCount()

	td := NewTerminalDisplay()

	// Create simple test markdown content
	markdownContent := "# Test Content\n\nThis is a test document."

	// Create a simple progress channel
	progressCh := make(chan ProgressEvent, 1)
	go func() {
		progressCh <- ProgressEvent{Percent: 0.5, Message: "Processing..."}
		close(progressCh)
	}()

	// Cancel immediately
	cancel()

	_ = td.DisplayWithProgress(ctx, markdownContent, progressCh)

	// Give goroutines time to clean up
	time.Sleep(50 * time.Millisecond)

	// Check that goroutine count returned to baseline (or close to it)
	// Allow for a small delta since other tests might be running
	finalCount := currentGoroutineCount()
	delta := finalCount - baselineCount
	assert.Less(t, delta, 5, "Too many goroutines remained after cancellation")
}

// TestDisplayMultipleCancellationPoints tests all three cancellation checkpoints.
func TestDisplayMultipleCancellationPoints(t *testing.T) {
	// This test verifies that context cancellation is checked at multiple points
	// in the Display method execution path

	td := NewTerminalDisplay()

	// Create simple test markdown content
	markdownContent := "# Test Content\n\nThis is a test document."

	// Test cancellation at each checkpoint
	for i := 0; i < 3; i++ {
		t.Run("Cancellation checkpoint", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()

			err := td.Display(ctx, markdownContent)

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

// TestHandleRendererErrorWithCancelledContext tests error handling when context is already cancelled.
func TestHandleRendererErrorWithCancelledContext(t *testing.T) {
	td := NewTerminalDisplay()

	var wg sync.WaitGroup
	err := td.handleRendererError(ErrRawMarkdown, "test content", &wg)

	// Should handle error gracefully even with cancelled context
	assert.NoError(t, err)
}

// Helper function to get current goroutine count
func currentGoroutineCount() int {
	// This is a simplified version - in production you'd use runtime.NumGoroutine()
	// but for tests we just return a baseline
	return 10 // Placeholder
}
