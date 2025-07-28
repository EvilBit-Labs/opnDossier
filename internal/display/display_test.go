package display

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/markdown"
)

func TestNewTerminalDisplay(t *testing.T) {
	td := NewTerminalDisplay()
	assert.NotNil(t, td)
	assert.NotNil(t, td.options)
	assert.NotNil(t, td.progress)
	assert.Equal(t, 120, td.options.WrapWidth) // Default value
	assert.True(t, td.options.EnableTables)
	assert.True(t, td.options.EnableColors)
}

func TestNewStyleSheet(t *testing.T) {
	ss := NewStyleSheet()
	assert.NotNil(t, ss)
	assert.NotNil(t, ss.Title)
	assert.NotNil(t, ss.Subtitle)
	assert.NotNil(t, ss.Table)
	assert.NotNil(t, ss.Error)
	assert.NotNil(t, ss.Warning)
}

func TestNewStyleSheetWithTheme(t *testing.T) {
	ss := NewStyleSheetWithTheme(LightTheme())
	assert.NotNil(t, ss)
	assert.Equal(t, LightTheme(), ss.theme)
}

func TestStyleSheetPrintMethods(t *testing.T) {
	ss := NewStyleSheet()

	// These methods print to stdout, so we can't easily test output
	// but we can ensure they don't panic
	assert.NotPanics(t, func() {
		ss.TitlePrint("Test Title")
	})
	assert.NotPanics(t, func() {
		ss.ErrorPrint("Test Error")
	})
	assert.NotPanics(t, func() {
		ss.WarningPrint("Test Warning")
	})
	assert.NotPanics(t, func() {
		ss.SubtitlePrint("Test Subtitle")
	})
	assert.NotPanics(t, func() {
		ss.TablePrint("Test Table")
	})
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	assert.Equal(t, DefaultWordWrapWidth, opts.WrapWidth)
	assert.True(t, opts.EnableTables)
	assert.True(t, opts.EnableColors)
	assert.NotNil(t, opts.Theme)
}

func TestConvertMarkdownOptions(t *testing.T) {
	// Create mock markdown options
	mdOpts := markdown.Options{
		Theme:        markdown.ThemeLight,
		WrapWidth:    100,
		EnableTables: true,
		EnableColors: false,
	}

	opts := convertMarkdownOptions(mdOpts)
	assert.Equal(t, LightTheme(), opts.Theme)
	assert.Equal(t, 100, opts.WrapWidth)
	assert.True(t, opts.EnableTables)
	assert.False(t, opts.EnableColors)
}

func TestNewTerminalDisplayWithOptions(t *testing.T) {
	opts := Options{
		Theme:        DarkTheme(),
		WrapWidth:    80,
		EnableTables: false,
		EnableColors: true,
	}

	td := NewTerminalDisplayWithOptions(opts)
	assert.NotNil(t, td)
	assert.Equal(t, 80, td.options.WrapWidth)
	assert.False(t, td.options.EnableTables)
	assert.True(t, td.options.EnableColors)
	assert.Equal(t, DarkTheme(), td.options.Theme)
}

func TestNewTerminalDisplayWithMarkdownOptions(t *testing.T) {
	mdOpts := markdown.Options{
		Theme:        markdown.ThemeDark,
		WrapWidth:    90,
		EnableTables: false,
		EnableColors: true,
	}

	td := NewTerminalDisplayWithMarkdownOptions(mdOpts)
	assert.NotNil(t, td)
	assert.Equal(t, 90, td.options.WrapWidth)
	assert.False(t, td.options.EnableTables)
	assert.True(t, td.options.EnableColors)
}

func TestGetTerminalWidth(t *testing.T) {
	// Test default behavior
	original := os.Getenv("COLUMNS")
	defer func() {
		if original != "" {
			err := os.Setenv("COLUMNS", original)
			require.NoError(t, err)
		} else {
			err := os.Unsetenv("COLUMNS")
			require.NoError(t, err)
		}
	}()

	err := os.Unsetenv("COLUMNS")
	require.NoError(t, err)
	width := getTerminalWidth()
	assert.Equal(t, DefaultWordWrapWidth, width)

	// Test with COLUMNS set
	err = os.Setenv("COLUMNS", "100")
	require.NoError(t, err)
	width = getTerminalWidth()
	assert.Equal(t, 100, width)

	// Test with invalid COLUMNS
	err = os.Setenv("COLUMNS", "invalid")
	require.NoError(t, err)
	width = getTerminalWidth()
	assert.Equal(t, DefaultWordWrapWidth, width)
}

func TestProgressEvent(t *testing.T) {
	event := ProgressEvent{
		Percent: 0.5,
		Message: "Test message",
	}
	assert.Equal(t, 0.5, event.Percent)
	assert.Equal(t, "Test message", event.Message)
}

func TestTerminalDisplayProgress(t *testing.T) {
	td := NewTerminalDisplay()

	// Test ShowProgress doesn't panic
	assert.NotPanics(t, func() {
		td.ShowProgress(0.5, "Test progress")
	})

	// Test ClearProgress doesn't panic
	assert.NotPanics(t, func() {
		td.ClearProgress()
	})
}

func TestTerminalDisplayShouldShowNavigationHints(t *testing.T) {
	td := NewTerminalDisplay()
	// Currently always returns false
	assert.False(t, td.shouldShowNavigationHints())
}

func TestTerminalDisplayShowNavigationHints(t *testing.T) {
	td := NewTerminalDisplay()
	// Should not panic
	assert.NotPanics(t, func() {
		td.showNavigationHints()
	})
}

func TestDeprecatedFunctions(t *testing.T) {
	// Test deprecated Title function
	assert.NotPanics(t, func() {
		Title("Test title")
	})

	// Test deprecated Error function
	assert.NotPanics(t, func() {
		Error("Test error")
	})
}

func TestDisplayWithProgressGoroutineLeakFix(t *testing.T) {
	td := NewTerminalDisplay()

	// Create a channel that will never be closed to test the leak scenario
	progressCh := make(chan ProgressEvent)

	// Start the display in a goroutine
	done := make(chan error, 1)
	go func() {
		err := td.DisplayWithProgress(context.Background(), "# Test Markdown", progressCh)
		done <- err
	}()

	// Send a few progress events
	progressCh <- ProgressEvent{Percent: 0.25, Message: "Processing..."}
	progressCh <- ProgressEvent{Percent: 0.5, Message: "Halfway..."}
	progressCh <- ProgressEvent{Percent: 0.75, Message: "Almost done..."}

	// Close the channel to signal completion
	close(progressCh)

	// Wait for the display to complete
	err := <-done
	assert.NoError(t, err)

	// The test passes if we reach here without hanging
	// The original code would have leaked the goroutine
}

func TestDisplayRawMarkdownWhenColorsDisabled(t *testing.T) {
	// Create display with colors disabled
	opts := Options{
		Theme:        LightTheme(),
		WrapWidth:    80,
		EnableTables: true,
		EnableColors: false,
	}
	td := NewTerminalDisplayWithOptions(opts)

	// Test markdown content with ANSI codes
	markdownContent := "# Test Header\n\nThis is **bold** and *italic* text.\n\n```go\nfunc test() {}\n```"

	// Capture stdout
	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() {
		os.Stdout = originalStdout
		if err := w.Close(); err != nil {
			t.Logf("failed to close pipe: %v", err)
		}
	}()

	// Run display
	err = td.Display(context.Background(), markdownContent)
	require.NoError(t, err)

	// Close write end and read output
	if err := w.Close(); err != nil {
		t.Logf("failed to close pipe: %v", err)
	}
	output := make([]byte, 1024)
	n, err := r.Read(output)
	require.NoError(t, err)
	outputStr := string(output[:n])

	// Verify raw markdown is output (no ANSI codes)
	assert.Contains(t, outputStr, "# Test Header")
	assert.Contains(t, outputStr, "**bold**")
	assert.Contains(t, outputStr, "*italic*")
	assert.Contains(t, outputStr, "```go")
	assert.Contains(t, outputStr, "func test() {}")
	assert.Contains(t, outputStr, "```")

	// Verify no ANSI escape sequences are present
	// ANSI codes start with \x1b[ (ESC [)
	assert.NotContains(t, outputStr, "\x1b[")
}

func TestDisplayWithANSIWhenColorsEnabled(t *testing.T) {
	// Create display with colors enabled
	opts := Options{
		Theme:        LightTheme(),
		WrapWidth:    80,
		EnableTables: true,
		EnableColors: true,
	}
	td := NewTerminalDisplayWithOptions(opts)

	// Test markdown content
	markdownContent := "# Test Header\n\nThis is **bold** and *italic* text.\n\n```go\nfunc test() {}\n```"

	// Capture stdout
	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() {
		os.Stdout = originalStdout
		if err := w.Close(); err != nil {
			t.Logf("failed to close pipe: %v", err)
		}
	}()

	// Run display
	err = td.Display(context.Background(), markdownContent)
	require.NoError(t, err)

	// Close write end and read output
	if err := w.Close(); err != nil {
		t.Logf("failed to close pipe: %v", err)
	}
	output := make([]byte, 8192) // Increased buffer size
	n, err := r.Read(output)
	require.NoError(t, err)
	outputStr := string(output[:n])

	// Verify ANSI escape sequences are present (indicating colored output)
	assert.Contains(t, outputStr, "\x1b[")

	// Verify some content is present (may be wrapped in ANSI codes)
	// The exact text might be split by ANSI codes, so we check for partial matches
	assert.True(t, strings.Contains(outputStr, "Test") || strings.Contains(outputStr, "Header"),
		"Expected to find 'Test' or 'Header' in output")
}

func TestDisplayWithProgressRawMarkdownWhenColorsDisabled(t *testing.T) {
	// Create display with colors disabled
	opts := Options{
		Theme:        LightTheme(),
		WrapWidth:    80,
		EnableTables: true,
		EnableColors: false,
	}
	td := NewTerminalDisplayWithOptions(opts)

	// Test markdown content
	markdownContent := "# Test Header\n\nThis is **bold** and *italic* text."

	// Create progress channel
	progressCh := make(chan ProgressEvent, 1)

	// Capture stdout
	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() {
		os.Stdout = originalStdout
		if err := w.Close(); err != nil {
			t.Logf("failed to close pipe: %v", err)
		}
	}()

	// Run display with progress
	done := make(chan error, 1)
	go func() {
		err := td.DisplayWithProgress(context.Background(), markdownContent, progressCh)
		done <- err
	}()

	// Send progress event and close channel
	progressCh <- ProgressEvent{Percent: 0.5, Message: "Processing..."}
	close(progressCh)

	// Wait for completion
	err = <-done
	require.NoError(t, err)

	// Close write end and read output
	if err := w.Close(); err != nil {
		t.Logf("failed to close pipe: %v", err)
	}
	output := make([]byte, 2048) // Increased buffer size
	n, err := r.Read(output)
	require.NoError(t, err)
	outputStr := string(output[:n])

	// Verify raw markdown is output
	assert.Contains(t, outputStr, "# Test Header")
	assert.Contains(t, outputStr, "**bold**")
	assert.Contains(t, outputStr, "*italic*")

	// Verify no ANSI escape sequences in the markdown content
	// (progress bar may still use ANSI codes for clearing lines)
	// Extract just the markdown content by looking for the actual text
	markdownSection := outputStr
	if idx := strings.Index(outputStr, "# Test Header"); idx != -1 {
		markdownSection = outputStr[idx:]
	}
	assert.Contains(t, markdownSection, "# Test Header")
	assert.Contains(t, markdownSection, "**bold**")
	assert.Contains(t, markdownSection, "*italic*")

	// The progress bar may use ANSI codes, but the markdown content should be raw
	// We can't easily separate them in the test, so we just verify the content is there
}

func TestDisplayWithProgressANSIWhenColorsEnabled(t *testing.T) {
	// Create display with colors enabled
	opts := Options{
		Theme:        LightTheme(),
		WrapWidth:    80,
		EnableTables: true,
		EnableColors: true,
	}
	td := NewTerminalDisplayWithOptions(opts)

	// Test markdown content
	markdownContent := "# Test Header\n\nThis is **bold** and *italic* text."

	// Create progress channel
	progressCh := make(chan ProgressEvent, 1)

	// Capture stdout
	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() {
		os.Stdout = originalStdout
		if err := w.Close(); err != nil {
			t.Logf("failed to close pipe: %v", err)
		}
	}()

	// Run display with progress
	done := make(chan error, 1)
	go func() {
		err := td.DisplayWithProgress(context.Background(), markdownContent, progressCh)
		done <- err
	}()

	// Send progress event and close channel
	progressCh <- ProgressEvent{Percent: 0.5, Message: "Processing..."}
	close(progressCh)

	// Wait for completion
	err = <-done
	require.NoError(t, err)

	// Close write end and read output
	if err := w.Close(); err != nil {
		t.Logf("failed to close pipe: %v", err)
	}
	output := make([]byte, 4096) // Increased buffer size
	n, err := r.Read(output)
	require.NoError(t, err)
	outputStr := string(output[:n])

	// Verify ANSI escape sequences are present
	assert.Contains(t, outputStr, "\x1b[")

	// Verify some content is present (may be wrapped in ANSI codes)
	assert.True(t, strings.Contains(outputStr, "Test") || strings.Contains(outputStr, "Header"),
		"Expected to find 'Test' or 'Header' in output")
}

func TestGlamourRendererWithDifferentColorSettings(t *testing.T) {
	// Test with colors enabled
	opts1 := Options{
		Theme:        LightTheme(),
		WrapWidth:    80,
		EnableTables: true,
		EnableColors: true,
	}
	renderer1, err1 := getGlamourRenderer(&opts1)
	assert.NoError(t, err1)
	assert.NotNil(t, renderer1)

	// Test with colors disabled
	opts2 := Options{
		Theme:        LightTheme(),
		WrapWidth:    80,
		EnableTables: true,
		EnableColors: false,
	}
	renderer2, err2 := getGlamourRenderer(&opts2)
	assert.Equal(t, ErrRawMarkdown, err2)
	assert.Nil(t, renderer2)
}

func TestErrRawMarkdownSentinel(t *testing.T) {
	// Test that our sentinel error is properly defined
	assert.Equal(t, "raw markdown display requested", ErrRawMarkdown.Error())
}
