// Package progress provides progress indication for CLI operations.
package progress

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Spinner animation constants.
const (
	spinnerIntervalMs = 80 // Milliseconds between spinner frame updates
)

// SpinnerProgress provides a spinning indicator for indeterminate operations.
type SpinnerProgress struct {
	output   io.Writer
	frames   []string
	interval time.Duration
	current  int
	message  string
	running  bool
	done     chan struct{}
	mu       sync.Mutex
}

// NewSpinner creates a new spinner progress indicator.
func NewSpinner(opts Options) *SpinnerProgress {
	output := opts.Output
	if output == nil {
		output = os.Stderr
	}

	return &SpinnerProgress{
		output:   output,
		frames:   []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		interval: spinnerIntervalMs * time.Millisecond,
		done:     make(chan struct{}),
	}
}

// Start begins the spinner animation with the given message.
func (s *SpinnerProgress) Start(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return
	}

	s.message = message
	s.running = true
	s.done = make(chan struct{})

	go s.spin()
}

// spin runs the spinner animation loop.
func (s *SpinnerProgress) spin() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.mu.Lock()
			s.current = (s.current + 1) % len(s.frames)
			frame := s.frames[s.current]
			msg := s.message
			s.mu.Unlock()

			// Clear line and print frame with message
			fmt.Fprintf(s.output, "\r\033[K%s %s", frame, msg)
		}
	}
}

// Update updates the spinner message. The percent is ignored for spinners.
func (s *SpinnerProgress) Update(_ float64, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.message = message
}

// Complete stops the spinner and shows a success message.
func (s *SpinnerProgress) Complete(message string) {
	s.stop()
	fmt.Fprintf(s.output, "\r\033[K✓ %s\n", message)
}

// Fail stops the spinner and shows an error message.
func (s *SpinnerProgress) Fail(err error) {
	s.stop()
	fmt.Fprintf(s.output, "\r\033[K✗ %v\n", err)
}

// stop stops the spinner animation.
func (s *SpinnerProgress) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	close(s.done)
}
