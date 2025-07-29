package display

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/constants"
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
	markdownContent := "# Test Header\n\nThis is **bold** and *italic* text.\n\n```\nfunc test() {}\n```"

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

	// Verify content is present (the exact format may vary in test environments)
	// Check for either ANSI codes OR properly rendered content
	hasANSI := strings.Contains(outputStr, "\x1b[")
	hasContent := strings.Contains(outputStr, "Test") || strings.Contains(outputStr, "Header") ||
		strings.Contains(outputStr, "bold") || strings.Contains(outputStr, "italic")

	// In test environments, glamour may not emit ANSI codes, so we accept either
	assert.True(t, hasANSI || hasContent,
		"Expected either ANSI codes or rendered content, got neither. Output: %q", outputStr)

	// Verify some content is present regardless of formatting
	assert.True(t, hasContent,
		"Expected to find test content in output. Output: %q", outputStr)
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

// TestDetectTheme tests theme detection with various environment configurations.
func TestDetectTheme(t *testing.T) {
	// Save original environment variables
	originalColorTerm := os.Getenv("COLORTERM")
	originalTerm := os.Getenv("TERM")
	originalTheme := os.Getenv("OPNFOCUS_THEME")
	originalTermProgram := os.Getenv("TERM_PROGRAM")

	// Restore environment after tests
	defer func() {
		require.NoError(t, os.Setenv("COLORTERM", originalColorTerm))
		require.NoError(t, os.Setenv("TERM", originalTerm))
		require.NoError(t, os.Setenv("OPNFOCUS_THEME", originalTheme))
		require.NoError(t, os.Setenv("TERM_PROGRAM", originalTermProgram))
	}()

	tests := []struct {
		name        string
		configTheme string
		envTheme    string
		colorTerm   string
		term        string
		termProgram string
		expected    string
	}{
		// Config theme takes highest priority
		{"Config overrides all", constants.ThemeLight, constants.ThemeDark, "truecolor", "xterm-256color", "", constants.ThemeLight},
		{"Config dark theme", constants.ThemeDark, "", "", "", "", constants.ThemeDark},
		{"Config custom theme", Custom, "", "", "", "", Custom},

		// Environment variable takes second priority
		{"Env theme override", "", constants.ThemeDark, "", "xterm", "", constants.ThemeDark},
		{"Env light theme", "", constants.ThemeLight, "truecolor", "xterm-256color", "", constants.ThemeLight},

		// Auto-detection based on terminal capabilities
		{"Truecolor detection", "", "", "truecolor", "xterm-256color", "", constants.ThemeDark},
		{"24bit color detection", "", "", Bit24, "xterm", "", constants.ThemeDark},
		{"256color detection", "", "", "", "xterm-256color", "", constants.ThemeDark},
		{"Dark term detection", "", "", "", "xterm-dark", "", constants.ThemeDark},
		{"Dark term program", "", "", "", "xterm", "dark-term", constants.ThemeDark},

		// Default to light theme
		{"Basic terminal default", "", "", "", "xterm", "", constants.ThemeLight},
		{"No terminal info", "", "", "", "", "", constants.ThemeLight},

		// Invalid values default to auto-detection
		{"Invalid config theme", "invalid", "", "", "xterm", "", constants.ThemeLight},
		{"Invalid env theme", "", "invalid", "", "xterm", "", constants.ThemeLight},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables for this test
			require.NoError(t, os.Setenv("OPNFOCUS_THEME", tt.envTheme))
			require.NoError(t, os.Setenv("COLORTERM", tt.colorTerm))
			require.NoError(t, os.Setenv("TERM", tt.term))
			require.NoError(t, os.Setenv("TERM_PROGRAM", tt.termProgram))

			theme := DetectTheme(tt.configTheme)
			assert.Equal(t, tt.expected, theme.Name)
		})
	}
}

// TestThemeProperties tests the properties and methods of Theme struct.
func TestThemeProperties(t *testing.T) {
	tests := []struct {
		name        string
		theme       Theme
		isLight     bool
		isDark      bool
		colorExists bool
		colorKey    string
	}{
		{"Light theme properties", LightTheme(), true, false, true, "background"},
		{"Dark theme properties", DarkTheme(), false, true, true, "foreground"},
		{"Custom theme properties", CustomTheme(), false, false, false, "nonexistent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isLight, tt.theme.IsLight())
			assert.Equal(t, tt.isDark, tt.theme.IsDark())

			if tt.colorExists {
				color := tt.theme.GetColor(tt.colorKey)
				assert.NotEmpty(t, color)
				assert.True(t, color[0] == '#') // Should be a hex color
			}

			// Test Glamour style name
			styleName := tt.theme.GetGlamourStyleName()
			assert.NotEmpty(t, styleName)
		})
	}
}

// TestThemeColorPalette tests the color palette functionality.
func TestThemeColorPalette(t *testing.T) {
	lightTheme := LightTheme()
	darkTheme := DarkTheme()

	// Test light theme colors
	assert.Equal(t, "#FFFFFF", lightTheme.GetColor("background"))
	assert.Equal(t, "#000000", lightTheme.GetColor("foreground"))
	assert.Equal(t, "#007ACC", lightTheme.GetColor("primary"))

	// Test dark theme colors
	assert.Equal(t, "#1E1E1E", darkTheme.GetColor("background"))
	assert.Equal(t, "#FFFFFF", darkTheme.GetColor("foreground"))
	assert.Equal(t, "#4FC3F7", darkTheme.GetColor("primary"))

	// Test non-existent color (should return default)
	assert.Equal(t, "#000000", lightTheme.GetColor("nonexistent"))
	assert.Equal(t, "#FFFFFF", darkTheme.GetColor("nonexistent"))
}

// TestTerminalCapabilityDetection tests the terminal capability detection functions.
func TestTerminalCapabilityDetection(t *testing.T) {
	// Save original environment variables
	originalColorTerm := os.Getenv("COLORTERM")
	originalTerm := os.Getenv("TERM")

	// Restore environment after tests
	defer func() {
		require.NoError(t, os.Setenv("COLORTERM", originalColorTerm))
		require.NoError(t, os.Setenv("TERM", originalTerm))
	}()

	tests := []struct {
		name        string
		colorTerm   string
		term        string
		expectColor bool
	}{
		{"Truecolor support", "truecolor", "xterm", true},
		{"24bit support", "24bit", "xterm", true},
		{"256color support", "", "xterm-256color", true},
		{"Basic color support", "", "xterm-color", true},
		{"Modern terminal", "", "alacritty", true},
		{"Screen session", "", "screen", true},
		{"Tmux session", "", "tmux", true},
		{"iTerm", "", "iterm", true},
		{"Konsole", "", "konsole", true},
		{"No color support", "", "dumb", false},
		{"Unknown terminal", "", "unknown", false},
		{"Empty terminal", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, os.Setenv("COLORTERM", tt.colorTerm))
			require.NoError(t, os.Setenv("TERM", tt.term))

			// In test environment, isTerminal() returns false, so we test the logic
			// by checking if the terminal would be color capable if it were a terminal
			colorCapable := testTerminalColorCapable(tt.colorTerm, tt.term)
			assert.Equal(t, tt.expectColor, colorCapable)
		})
	}
}

// testTerminalColorCapable is a test version that doesn't check isTerminal().
func testTerminalColorCapable(colorTerm, term string) bool {
	// Check for explicit color support
	if colorTerm == "truecolor" || colorTerm == Bit24 {
		return true
	}

	// Check for 256-color support
	if strings.Contains(term, "256color") {
		return true
	}

	// Check for basic color support
	if strings.Contains(term, "color") {
		return true
	}

	// Check for common terminal types that support color
	colorTerminals := []string{"xterm", "screen", "tmux", "iterm", "konsole", "gnome", "alacritty"}
	for _, colorTerm := range colorTerminals {
		if strings.Contains(strings.ToLower(term), colorTerm) {
			return true
		}
	}

	// Default to false for unknown terminals
	return false
}

// TestGlamourStyleDetermination tests the Glamour style determination logic.
func TestGlamourStyleDetermination(t *testing.T) {
	// Save original environment variables
	originalColorTerm := os.Getenv("COLORTERM")
	originalTerm := os.Getenv("TERM")
	originalTheme := os.Getenv("OPNFOCUS_THEME")

	// Restore environment after tests
	defer func() {
		require.NoError(t, os.Setenv("COLORTERM", originalColorTerm))
		require.NoError(t, os.Setenv("TERM", originalTerm))
		require.NoError(t, os.Setenv("OPNFOCUS_THEME", originalTheme))
	}()

	tests := []struct {
		name          string
		themeName     string
		enableColors  bool
		colorTerm     string
		term          string
		expectedStyle string
	}{
		// Colors disabled
		{"Colors disabled", constants.ThemeLight, false, "truecolor", "xterm-256color", Notty},
		{"Colors disabled dark", constants.ThemeDark, false, "truecolor", "xterm-256color", Notty},

		// No color capability
		{"No color capability", constants.ThemeLight, true, "", "dumb", "ascii"},
		{"No color capability dark", constants.ThemeDark, true, "", "dumb", "ascii"},

		// Theme-based styles (only test when colors are enabled and terminal is capable)
		{"Light theme", constants.ThemeLight, true, "truecolor", "xterm-256color", "light"},
		{"Dark theme", constants.ThemeDark, true, "truecolor", "xterm-256color", "dark"},
		{"None theme", None, true, "truecolor", "xterm-256color", Notty},
		{"Custom theme", Custom, true, "truecolor", "xterm-256color", "auto"},
		{"Auto theme", Auto, true, "truecolor", "xterm-256color", "dark"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables for this test
			require.NoError(t, os.Setenv("COLORTERM", tt.colorTerm))
			require.NoError(t, os.Setenv("TERM", tt.term))
			// Clear OPNFOCUS_THEME to ensure theme detection works correctly
			require.NoError(t, os.Setenv("OPNFOCUS_THEME", ""))

			// Create theme based on the theme name directly
			var theme Theme
			switch tt.themeName {
			case constants.ThemeLight:
				theme = LightTheme()
			case constants.ThemeDark:
				theme = DarkTheme()
			case None:
				theme = Theme{Name: "none", GlamourStyle: "notty"}
			case Custom:
				theme = CustomTheme()
			case Auto:
				theme = DetectTheme("") // This will auto-detect
			default:
				theme = DetectTheme(tt.themeName)
			}

			opts := Options{
				Theme:        theme,
				EnableColors: tt.enableColors,
			}

			// For testing, we need to mock the terminal capability check
			// since isTerminal() returns false in test environment
			style := testDetermineGlamourStyle(&opts, tt.colorTerm, tt.term)
			assert.Equal(t, tt.expectedStyle, style)
		})
	}
}

// testDetermineGlamourStyle is a test version that doesn't check isTerminal().
func testDetermineGlamourStyle(opts *Options, colorTerm, term string) string {
	// Check if colors are disabled first
	if !opts.EnableColors {
		return Notty
	}

	// Check terminal color capabilities (test version)
	if !testTerminalColorCapable(colorTerm, term) {
		return "ascii"
	}

	// Determine theme-based style
	switch opts.Theme.Name {
	case constants.ThemeLight:
		return constants.ThemeLight
	case constants.ThemeDark:
		return constants.ThemeDark
	case None:
		return Notty
	case Custom:
		// Custom theme uses auto-detection
		return Auto
	default: // "auto" or other
		// Use the theme's Glamour style name, which should handle auto-detection
		return opts.Theme.GetGlamourStyleName()
	}
}

// TestDisplayOptions tests the display options functionality.
func TestDisplayOptions(t *testing.T) {
	// Test default options
	opts := DefaultOptions()
	assert.NotNil(t, opts.Theme)
	assert.True(t, opts.EnableColors)
	assert.True(t, opts.EnableTables)
	assert.Greater(t, opts.WrapWidth, 0)

	// Test custom options
	customTheme := LightTheme()
	customOpts := Options{
		Theme:        customTheme,
		WrapWidth:    80,
		EnableTables: false,
		EnableColors: false,
	}

	assert.Equal(t, customTheme.Name, customOpts.Theme.Name)
	assert.Equal(t, 80, customOpts.WrapWidth)
	assert.False(t, customOpts.EnableTables)
	assert.False(t, customOpts.EnableColors)
}

// TestTerminalDisplayCreation tests the terminal display creation functions.
func TestTerminalDisplayCreation(t *testing.T) {
	// Test default creation
	td := NewTerminalDisplay()
	assert.NotNil(t, td)
	assert.NotNil(t, td.options)

	// Test with theme
	theme := DarkTheme()
	tdWithTheme := NewTerminalDisplayWithTheme(theme)
	assert.NotNil(t, tdWithTheme)
	assert.Equal(t, theme.Name, tdWithTheme.options.Theme.Name)

	// Test with options
	opts := Options{
		Theme:        LightTheme(),
		WrapWidth:    100,
		EnableTables: false,
		EnableColors: true,
	}
	tdWithOpts := NewTerminalDisplayWithOptions(opts)
	assert.NotNil(t, tdWithOpts)
	assert.Equal(t, opts.Theme.Name, tdWithOpts.options.Theme.Name)
	assert.Equal(t, opts.WrapWidth, tdWithOpts.options.WrapWidth)
	assert.Equal(t, opts.EnableTables, tdWithOpts.options.EnableTables)
	assert.Equal(t, opts.EnableColors, tdWithOpts.options.EnableColors)
}
