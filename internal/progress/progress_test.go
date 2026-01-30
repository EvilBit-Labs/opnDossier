package progress

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()

	if opts.Width != DefaultProgressWidth {
		t.Errorf("DefaultOptions().Width = %d, want %d", opts.Width, DefaultProgressWidth)
	}
	if !opts.ShowPercentage {
		t.Error("DefaultOptions().ShowPercentage = false, want true")
	}
	if !opts.Enabled {
		t.Error("DefaultOptions().Enabled = false, want true")
	}
	if opts.Output == nil {
		t.Error("DefaultOptions().Output = nil, want non-nil")
	}
}

func TestNewWithDisabledReturnsNoOp(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()
	opts.Enabled = false

	p := New(opts)

	_, ok := p.(*NoOpProgress)
	if !ok {
		t.Errorf("New() with Enabled=false should return *NoOpProgress, got %T", p)
	}
}

func TestNewWithNonTerminalReturnsNoOp(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	opts := DefaultOptions()
	opts.Output = &buf // Non-terminal output

	p := New(opts)

	_, ok := p.(*NoOpProgress)
	if !ok {
		t.Errorf("New() with non-terminal output should return *NoOpProgress, got %T", p)
	}
}

func TestNewForMultiFileWithDisabledReturnsNoOp(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()
	opts.Enabled = false

	p := NewForMultiFile(opts)

	_, ok := p.(*NoOpProgress)
	if !ok {
		t.Errorf("NewForMultiFile() with Enabled=false should return *NoOpProgress, got %T", p)
	}
}

func TestNewForMultiFileWithNonTerminalReturnsNoOp(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	opts := DefaultOptions()
	opts.Output = &buf // Non-terminal output

	p := NewForMultiFile(opts)

	_, ok := p.(*NoOpProgress)
	if !ok {
		t.Errorf("NewForMultiFile() with non-terminal output should return *NoOpProgress, got %T", p)
	}
}

func TestIsTerminalWithNonFile(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if isTerminal(&buf) {
		t.Error("isTerminal() with bytes.Buffer should return false")
	}
}

func TestNoOpProgressImplementsInterface(t *testing.T) {
	t.Parallel()

	var p Progress = NewNoOp()

	// These should not panic
	p.Start("test")
	p.Update(0.5, "testing")
	p.Complete("done")
	p.Fail(errors.New("error"))
}

func TestNoOpProgressDoesNothing(t *testing.T) {
	t.Parallel()

	noop := NewNoOp()

	// All these should be safe to call and do nothing
	noop.Start("test")
	noop.Update(0.5, "testing")
	noop.Complete("done")
	noop.Fail(errors.New("error"))
}

func TestSpinnerWithNilOutput(t *testing.T) {
	t.Parallel()

	opts := Options{
		Output:  nil,
		Enabled: true,
	}

	spinner := NewSpinner(opts)
	if spinner.output == nil {
		t.Error("NewSpinner() with nil output should use default output")
	}
}

func TestSpinnerStartAndComplete(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	spinner := NewSpinner(Options{
		Output:  &buf,
		Enabled: true,
	})

	spinner.Start("Processing")
	time.Sleep(100 * time.Millisecond) // Let spinner run a bit
	spinner.Complete("Done")

	output := buf.String()
	if !strings.Contains(output, "Done") {
		t.Errorf("Complete() should write message, got %q", output)
	}
	if !strings.Contains(output, "✓") {
		t.Errorf("Complete() should include checkmark, got %q", output)
	}
}

func TestSpinnerStartAndFail(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	spinner := NewSpinner(Options{
		Output:  &buf,
		Enabled: true,
	})

	spinner.Start("Processing")
	time.Sleep(100 * time.Millisecond) // Let spinner run a bit
	spinner.Fail(errors.New("something went wrong"))

	output := buf.String()
	if !strings.Contains(output, "something went wrong") {
		t.Errorf("Fail() should write error message, got %q", output)
	}
	if !strings.Contains(output, "✗") {
		t.Errorf("Fail() should include x mark, got %q", output)
	}
}

func TestSpinnerUpdate(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	spinner := NewSpinner(Options{
		Output:  &buf,
		Enabled: true,
	})

	spinner.Start("Initial message")
	spinner.Update(0.5, "Updated message")
	time.Sleep(150 * time.Millisecond) // Let spinner run to see the update
	spinner.Complete("Done")

	output := buf.String()
	if !strings.Contains(output, "Updated message") {
		t.Errorf("Update() should change message, got %q", output)
	}
}

func TestSpinnerDoubleStartIgnored(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	spinner := NewSpinner(Options{
		Output:  &buf,
		Enabled: true,
	})

	spinner.Start("First")
	spinner.Start("Second") // Should be ignored
	time.Sleep(100 * time.Millisecond)
	spinner.Complete("Done")

	// Test should complete without deadlock or panic
}

func TestSpinnerStopIdempotent(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	spinner := NewSpinner(Options{
		Output:  &buf,
		Enabled: true,
	})

	spinner.Start("Processing")
	time.Sleep(50 * time.Millisecond)
	spinner.Complete("First")
	spinner.Complete("Second") // Should be safe to call again

	// Test should complete without deadlock or panic
}
