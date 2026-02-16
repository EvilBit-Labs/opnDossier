package progress

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestNewBar(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		opts          Options
		expectOutput  bool
		expectWidth   int
		expectShowPct bool
	}{
		{
			name:          "default options",
			opts:          Options{},
			expectOutput:  true, // Should default to os.Stderr
			expectWidth:   40,   // Default width
			expectShowPct: false,
		},
		{
			name: "custom output writer",
			opts: Options{
				Output:         &bytes.Buffer{},
				Width:          50,
				ShowPercentage: true,
			},
			expectOutput:  true,
			expectWidth:   50,
			expectShowPct: true,
		},
		{
			name: "nil output defaults to stderr",
			opts: Options{
				Output: nil,
				Width:  30,
			},
			expectOutput:  true,
			expectWidth:   30,
			expectShowPct: false,
		},
		{
			name: "zero width defaults to 40",
			opts: Options{
				Output: &bytes.Buffer{},
				Width:  0,
			},
			expectOutput:  true,
			expectWidth:   40,
			expectShowPct: false,
		},
		{
			name: "negative width defaults to 40",
			opts: Options{
				Output: &bytes.Buffer{},
				Width:  -10,
			},
			expectOutput:  true,
			expectWidth:   40,
			expectShowPct: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bar := NewBar(tt.opts)

			if bar == nil {
				t.Fatal("NewBar() returned nil")
			}

			if tt.expectOutput && bar.output == nil {
				t.Error("NewBar() should have non-nil output")
			}

			if bar.width != tt.expectWidth {
				t.Errorf("NewBar().width = %d, want %d", bar.width, tt.expectWidth)
			}

			if bar.showPercentage != tt.expectShowPct {
				t.Errorf("NewBar().showPercentage = %v, want %v", bar.showPercentage, tt.expectShowPct)
			}

			// Check that defaults are properly set for nil output
			if tt.opts.Output == nil && bar.output != os.Stderr {
				t.Error("NewBar() with nil output should default to os.Stderr")
			}
		})
	}
}

func TestBarStart(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	bar := NewBar(Options{
		Output:         &buf,
		Width:          20,
		ShowPercentage: false,
	})

	bar.Start("Starting process")

	output := buf.String()
	if !strings.Contains(output, "Starting process") {
		t.Errorf("Start() should write message, got %q", output)
	}

	// Should contain progress bar with all empty blocks at start
	if !strings.Contains(output, "░") {
		t.Errorf("Start() should write progress bar, got %q", output)
	}

	// Should start with carriage return and clear sequence
	if !strings.HasPrefix(output, "\r\033[K") {
		t.Errorf("Start() should begin with clear sequence, got %q", output)
	}
}

func TestBarStartWithPercentage(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	bar := NewBar(Options{
		Output:         &buf,
		Width:          20,
		ShowPercentage: true,
	})

	bar.Start("Starting with percentage")

	output := buf.String()
	if !strings.Contains(output, "Starting with percentage") {
		t.Errorf("Start() should write message, got %q", output)
	}

	// Should contain 0% at start
	if !strings.Contains(output, "  0%") {
		t.Errorf("Start() should show 0%%, got %q", output)
	}
}

func TestBarUpdate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		percent      float64
		message      string
		expectPct    string
		expectFilled bool
	}{
		{
			name:         "25% progress",
			percent:      0.25,
			message:      "Quarter done",
			expectPct:    " 25%",
			expectFilled: true,
		},
		{
			name:         "50% progress",
			percent:      0.5,
			message:      "Half done",
			expectPct:    " 50%",
			expectFilled: true,
		},
		{
			name:         "75% progress",
			percent:      0.75,
			message:      "Three quarters done",
			expectPct:    " 75%",
			expectFilled: true,
		},
		{
			name:         "100% progress",
			percent:      1.0,
			message:      "Complete",
			expectPct:    "100%",
			expectFilled: true,
		},
		{
			name:         "0% progress",
			percent:      0.0,
			message:      "Starting",
			expectPct:    "  0%",
			expectFilled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			bar := NewBar(Options{
				Output:         &buf,
				Width:          20,
				ShowPercentage: true,
			})

			bar.Start("Initial")
			buf.Reset() // Clear start output

			bar.Update(tt.percent, tt.message)

			output := buf.String()
			if !strings.Contains(output, tt.message) {
				t.Errorf("Update() should write message %q, got %q", tt.message, output)
			}

			if !strings.Contains(output, tt.expectPct) {
				t.Errorf("Update() should show %s, got %q", tt.expectPct, output)
			}

			if tt.expectFilled && !strings.Contains(output, "█") {
				t.Errorf("Update() should show filled blocks for %f progress, got %q", tt.percent, output)
			}

			if !tt.expectFilled && strings.Contains(output, "█") {
				t.Errorf("Update() should not show filled blocks for %f progress, got %q", tt.percent, output)
			}
		})
	}
}

func TestBarUpdateWithoutPercentage(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	bar := NewBar(Options{
		Output:         &buf,
		Width:          20,
		ShowPercentage: false,
	})

	bar.Start("Initial")
	buf.Reset() // Clear start output

	bar.Update(0.5, "Half done")

	output := buf.String()
	if !strings.Contains(output, "Half done") {
		t.Errorf("Update() should write message, got %q", output)
	}

	// Should not contain percentage when ShowPercentage is false
	if strings.Contains(output, "%") {
		t.Errorf("Update() should not show percentage when ShowPercentage=false, got %q", output)
	}

	// Should still contain progress bar
	if !strings.Contains(output, "█") {
		t.Errorf("Update() should show filled blocks at 50%%, got %q", output)
	}
	if !strings.Contains(output, "░") {
		t.Errorf("Update() should show empty blocks at 50%%, got %q", output)
	}
}

func TestBarUpdateEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		percent    float64
		expectPct  string
		expectFull bool
	}{
		{
			name:       "negative percent clamped to 0",
			percent:    -0.5,
			expectPct:  "  0%",
			expectFull: false,
		},
		{
			name:       "percent greater than 1 clamped to 100",
			percent:    1.5,
			expectPct:  "100%",
			expectFull: true,
		},
		{
			name:       "very large percent clamped to 100",
			percent:    999.9,
			expectPct:  "100%",
			expectFull: true,
		},
		{
			name:       "very small negative percent clamped to 0",
			percent:    -999.9,
			expectPct:  "  0%",
			expectFull: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			bar := NewBar(Options{
				Output:         &buf,
				Width:          10,
				ShowPercentage: true,
			})

			bar.Start("Initial")
			buf.Reset()

			bar.Update(tt.percent, "Test")

			output := buf.String()
			if !strings.Contains(output, tt.expectPct) {
				t.Errorf("Update(%f) should show %s, got %q", tt.percent, tt.expectPct, output)
			}

			containsFilled := strings.Contains(output, "█")
			if tt.expectFull && !containsFilled {
				t.Errorf("Update(%f) should show filled blocks, got %q", tt.percent, output)
			}
			if !tt.expectFull && containsFilled {
				t.Errorf("Update(%f) should not show filled blocks, got %q", tt.percent, output)
			}
		})
	}
}

func TestBarComplete(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		showPercent   bool
		expectPercent bool
	}{
		{
			name:          "complete with percentage",
			showPercent:   true,
			expectPercent: true,
		},
		{
			name:          "complete without percentage",
			showPercent:   false,
			expectPercent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			bar := NewBar(Options{
				Output:         &buf,
				Width:          10,
				ShowPercentage: tt.showPercent,
			})

			bar.Start("Processing")
			buf.Reset() // Clear start output

			bar.Complete("Task completed")

			output := buf.String()
			if !strings.Contains(output, "Task completed") {
				t.Errorf("Complete() should write message, got %q", output)
			}

			// Should show 100% filled bar
			if !strings.Contains(output, "█") {
				t.Errorf("Complete() should show filled progress bar, got %q", output)
			}

			// Should not contain empty blocks when complete
			if strings.Contains(output, "░") {
				t.Errorf("Complete() should not show empty blocks, got %q", output)
			}

			if tt.expectPercent {
				if !strings.Contains(output, "100%") {
					t.Errorf("Complete() should show 100%% when ShowPercentage=true, got %q", output)
				}
			} else {
				if strings.Contains(output, "%") {
					t.Errorf("Complete() should not show percentage when ShowPercentage=false, got %q", output)
				}
			}

			// Should end with newline
			if !strings.HasSuffix(output, "\n") {
				t.Errorf("Complete() should end with newline, got %q", output)
			}
		})
	}
}

func TestBarFail(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	bar := NewBar(Options{
		Output:         &buf,
		Width:          20,
		ShowPercentage: true,
	})

	bar.Start("Processing")
	buf.Reset() // Clear start output

	testErr := errors.New("something went wrong")
	bar.Fail(testErr)

	output := buf.String()
	if !strings.Contains(output, "something went wrong") {
		t.Errorf("Fail() should write error message, got %q", output)
	}

	if !strings.Contains(output, "✗") {
		t.Errorf("Fail() should include x mark, got %q", output)
	}

	// Should start with clear sequence
	if !strings.HasPrefix(output, "\r\033[K") {
		t.Errorf("Fail() should begin with clear sequence, got %q", output)
	}

	// Should end with newline
	if !strings.HasSuffix(output, "\n") {
		t.Errorf("Fail() should end with newline, got %q", output)
	}
}

func TestBarImplementsInterface(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	var p Progress = NewBar(Options{Output: &buf})

	// These should not panic
	p.Start("test")
	p.Update(0.5, "testing")
	p.Complete("done")

	// Create a new instance for Fail test since Complete already finished
	p = NewBar(Options{Output: &buf})
	p.Fail(errors.New("error"))
}

func TestBarProgressBarRendering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		width        int
		percent      float64
		expectFilled int
		expectEmpty  int
	}{
		{
			name:         "width 10, 0% progress",
			width:        10,
			percent:      0.0,
			expectFilled: 0,
			expectEmpty:  10,
		},
		{
			name:         "width 10, 50% progress",
			width:        10,
			percent:      0.5,
			expectFilled: 5,
			expectEmpty:  5,
		},
		{
			name:         "width 10, 100% progress",
			width:        10,
			percent:      1.0,
			expectFilled: 10,
			expectEmpty:  0,
		},
		{
			name:         "width 20, 25% progress",
			width:        20,
			percent:      0.25,
			expectFilled: 5,
			expectEmpty:  15,
		},
		{
			name:         "width 1, 50% progress",
			width:        1,
			percent:      0.5,
			expectFilled: 0, // Should round down
			expectEmpty:  1,
		},
		{
			name:         "width 1, 100% progress",
			width:        1,
			percent:      1.0,
			expectFilled: 1,
			expectEmpty:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			bar := NewBar(Options{
				Output:         &buf,
				Width:          tt.width,
				ShowPercentage: false,
			})

			bar.Update(tt.percent, "Test")

			output := buf.String()

			filledCount := strings.Count(output, "█")
			emptyCount := strings.Count(output, "░")

			if filledCount != tt.expectFilled {
				t.Errorf("Expected %d filled blocks, got %d in output: %q", tt.expectFilled, filledCount, output)
			}

			if emptyCount != tt.expectEmpty {
				t.Errorf("Expected %d empty blocks, got %d in output: %q", tt.expectEmpty, emptyCount, output)
			}

			totalBlocks := filledCount + emptyCount
			if totalBlocks != tt.width {
				t.Errorf("Expected total blocks to equal width %d, got %d", tt.width, totalBlocks)
			}
		})
	}
}

func TestBarConcurrentAccess(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	bar := NewBar(Options{
		Output:         &buf,
		Width:          20,
		ShowPercentage: true,
	})

	// Test that concurrent access doesn't cause data races
	// This test mainly ensures proper mutex usage
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := range 100 {
			bar.Update(float64(i)/100, "Processing")
		}
	}()

	go func() {
		for i := range 100 {
			bar.Update(float64(i)/100, "Working")
		}
	}()

	<-done

	bar.Complete("Done")

	// Test should complete without data race
	output := buf.String()
	if !strings.Contains(output, "Done") {
		t.Errorf("Final Complete() message not found in output: %q", output)
	}
}
