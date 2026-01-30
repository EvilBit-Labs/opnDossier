// Package progress provides progress indication for CLI operations.
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Progress bar constants.
const (
	percentMultiplier = 100 // Multiplier to convert decimal to percentage
)

// BarProgress provides a visual progress bar for determinate operations.
type BarProgress struct {
	output         io.Writer
	width          int
	showPercentage bool
	percent        float64
	message        string
	mu             sync.Mutex
}

// NewBar creates a new bar progress indicator.
func NewBar(opts Options) *BarProgress {
	output := opts.Output
	if output == nil {
		output = os.Stderr
	}

	width := opts.Width
	if width <= 0 {
		width = 40
	}

	return &BarProgress{
		output:         output,
		width:          width,
		showPercentage: opts.ShowPercentage,
	}
}

// Start begins progress indication with an initial message.
func (b *BarProgress) Start(message string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.message = message
	b.percent = 0
	b.render()
}

// Update updates the progress bar with a new percentage and message.
func (b *BarProgress) Update(percent float64, message string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Clamp percent to [0, 1]
	if percent < 0 {
		percent = 0
	}
	if percent > 1 {
		percent = 1
	}

	b.percent = percent
	b.message = message
	b.render()
}

// Complete marks the progress as successfully completed.
func (b *BarProgress) Complete(message string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.percent = 1
	b.message = message
	b.render()

	// Move to new line after completion
	fmt.Fprintln(b.output)
}

// Fail marks the progress as failed with an error.
func (b *BarProgress) Fail(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Clear line and show error
	fmt.Fprintf(b.output, "\r\033[K✗ %v\n", err)
}

// render draws the progress bar to the output.
func (b *BarProgress) render() {
	// Calculate filled width
	filled := min(int(b.percent*float64(b.width)), b.width)

	// Build the bar
	bar := strings.Repeat("█", filled) + strings.Repeat("░", b.width-filled)

	// Build the output line
	if b.showPercentage {
		percentage := int(b.percent * percentMultiplier)
		fmt.Fprintf(b.output, "\r\033[K[%s] %3d%% %s", bar, percentage, b.message)
	} else {
		fmt.Fprintf(b.output, "\r\033[K[%s] %s", bar, b.message)
	}
}
