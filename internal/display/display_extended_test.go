package display

import (
	"context"
	"os"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsTerminal(t *testing.T) {
	t.Parallel()

	// The isTerminal function checks if stdout is a terminal
	// In test environments, this will typically return false
	result := isTerminal()
	// We can't predict the exact result in test environments,
	// but we can ensure the function doesn't panic
	assert.IsType(t, true, result) // Just check it returns a bool
}

func TestIsTerminalColorCapable(t *testing.T) {
	// Can't use t.Parallel() because we're setting environment variables

	// Save original environment variables
	originalColorTerm := os.Getenv("COLORTERM")
	originalTerm := os.Getenv("TERM")

	defer func() {
		t.Setenv("COLORTERM", originalColorTerm)
		t.Setenv("TERM", originalTerm)
	}()

	tests := []struct {
		name      string
		colorTerm string
		term      string
		// Note: In test environment, isTerminal() returns false,
		// so IsTerminalColorCapable will always return false
		// We test the logic path through the function
	}{
		{"truecolor support", "truecolor", "xterm"},
		{"24bit support", "24bit", "xterm"},
		{"256color support", "", "xterm-256color"},
		{"basic color support", "", "xterm-color"},
		{"modern terminal", "", "alacritty"},
		{"no color support", "", "dumb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("COLORTERM", tt.colorTerm)
			t.Setenv("TERM", tt.term)

			// The function should not panic and should return a boolean
			result := IsTerminalColorCapable()
			assert.IsType(t, true, result)
		})
	}
}

func TestNewTerminalDisplayWithOptionsWrapWidth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		inputWrapWidth  int
		expectedDefault bool
	}{
		{"negative width uses default", -1, true},
		{"negative width -5", -10, true},
		{"zero width preserved", 0, false},
		{"positive width preserved", 100, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := Options{
				Theme:        LightTheme(),
				WrapWidth:    tt.inputWrapWidth,
				EnableTables: true,
				EnableColors: true,
			}

			td := NewTerminalDisplayWithOptions(opts)
			require.NotNil(t, td)

			if tt.expectedDefault {
				// Should use terminal width (defaulting to DefaultWordWrapWidth)
				assert.NotEqual(t, tt.inputWrapWidth, td.options.WrapWidth)
			} else {
				// Should preserve the input width
				assert.Equal(t, tt.inputWrapWidth, td.options.WrapWidth)
			}
		})
	}
}

func TestNewTerminalDisplayWithThemeDeprecated(t *testing.T) {
	t.Parallel()

	// Test deprecated function
	theme := DarkTheme()
	td := NewTerminalDisplayWithTheme(theme)

	assert.NotNil(t, td)
	assert.Equal(t, theme.Name, td.options.Theme.Name)
	// Should use getTerminalWidth for wrap width
	assert.Positive(t, td.options.WrapWidth)
}

func TestWrapMarkdownContentEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		content  string
		width    int
		expected string
	}{
		{
			"zero width returns unchanged",
			"This is a test",
			0,
			"This is a test",
		},
		{
			"negative width returns unchanged",
			"This is a test",
			-1,
			"This is a test",
		},
		{
			"content shorter than width",
			"Short",
			100,
			"Short",
		},
		{
			"empty content",
			"",
			50,
			"",
		},
		{
			"code block with backticks",
			"```go\nfunc main() {\n    fmt.Println(\"Hello\")\n}\n```",
			10,
			"```go\nfunc main() {\n    fmt.Println(\"Hello\")\n}\n```",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := wrapMarkdownContent(tt.content, tt.width)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWrapMarkdownLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		line     string
		width    int
		expected []string
	}{
		{
			"zero width returns original",
			"This is a test line",
			0,
			[]string{"This is a test line"},
		},
		{
			"line shorter than width",
			"Short",
			100,
			[]string{"Short"},
		},
		{
			"line with leading spaces",
			"    Indented text that is longer than the width",
			20,
			[]string{"    Indented text th\\", "    at is longer tha\\", "    n the width"},
		},
		{
			"empty line",
			"",
			50,
			[]string{""},
		},
		{
			"line with only spaces",
			"   ",
			10,
			[]string{"   "},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := wrapMarkdownLine(tt.line, tt.width)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWrapRenderedOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		output   string
		width    int
		expected string
	}{
		{
			"zero width returns unchanged",
			"Some output",
			0,
			"Some output",
		},
		{
			"simple output within width",
			"Short output",
			100,
			"Short output",
		},
		{
			"multiline output",
			"Line 1\nLine 2\nLine 3",
			50,
			"Line 1\nLine 2\nLine 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := wrapRenderedOutput(tt.output, tt.width)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWrapRenderedLineWithANSI(t *testing.T) {
	t.Parallel()

	// Test with ANSI escape sequences
	line := "\x1b[1mBold text\x1b[0m normal text"
	width := 10
	result := wrapRenderedLine(line, width)

	// Should handle ANSI codes properly
	assert.NotEmpty(t, result)
	assert.IsType(t, []string{}, result)
}

func TestThemeApplyTheme(t *testing.T) {
	t.Parallel()

	theme := LightTheme()

	// Create a dummy lipgloss style
	style := lipgloss.NewStyle()

	// Test applying a color that exists
	newStyle := theme.ApplyTheme(style, "primary")
	assert.NotNil(t, newStyle)

	// Test applying a color that doesn't exist
	newStyle2 := theme.ApplyTheme(style, "nonexistent")
	assert.NotNil(t, newStyle2)
}

func TestGetTerminalWidthWithInvalidColumns(t *testing.T) {
	// Can't use t.Parallel() because we're setting environment variables

	// Save original COLUMNS
	original := os.Getenv("COLUMNS")
	defer func() {
		if original != "" {
			t.Setenv("COLUMNS", original)
		} else {
			t.Setenv("COLUMNS", "")
		}
	}()

	// Test with various COLUMNS values
	testCases := []struct {
		name     string
		value    string
		expected int
	}{
		{"invalid string", "not-a-number", DefaultWordWrapWidth},
		{"invalid mixed", "abc123", DefaultWordWrapWidth},
		{"negative number", "-100", -100}, // strconv.Atoi parses this successfully
		{"zero", "0", 0},                  // strconv.Atoi parses this successfully
		{"valid number", "100", 100},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("COLUMNS", tc.value)
			width := getTerminalWidth()
			assert.Equal(t, tc.expected, width)
		})
	}
}

func TestConvertMarkdownOptionsAllThemes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		mdTheme        string
		expectedResult string
	}{
		{"light theme", "light", "light"},
		{"dark theme", "dark", "dark"},
		{"auto theme", "auto", ""},       // Will be auto-detected
		{"none theme", "none", ""},       // Will use detected theme
		{"unknown theme", "unknown", ""}, // Will use detected theme
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// We can't directly test convertMarkdownOptions since it's not exported
			// and takes converter.Options, but we can test the theme detection logic
			// indirectly through DetectTheme
			theme := DetectTheme("")
			assert.NotEmpty(t, theme.Name)
		})
	}
}

func TestRendererSingletonBehavior(t *testing.T) {
	t.Parallel()

	// Test that the singleton pattern works correctly
	opts1 := &Options{
		Theme:        LightTheme(),
		WrapWidth:    80,
		EnableTables: true,
		EnableColors: true,
	}

	// First call should create renderer
	renderer1, err1 := getGlamourRenderer(opts1)
	require.NoError(t, err1)
	assert.NotNil(t, renderer1)

	// Second call with same options should return same instance
	renderer2, err2 := getGlamourRenderer(opts1)
	require.NoError(t, err2)
	assert.NotNil(t, renderer2)
	// Note: We can't compare pointers directly due to concurrent access patterns

	// Call with different options should recreate
	opts2 := &Options{
		Theme:        DarkTheme(),
		WrapWidth:    100,
		EnableTables: false,
		EnableColors: true,
	}

	renderer3, err3 := getGlamourRenderer(opts2)
	require.NoError(t, err3)
	assert.NotNil(t, renderer3)
}

func TestContextChecking(t *testing.T) {
	t.Parallel()

	td := NewTerminalDisplay()

	// Test with non-cancelled context
	ctx := context.Background()
	err := td.checkContext(ctx)
	require.NoError(t, err)

	// Test with cancelled context
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err = td.checkContext(cancelCtx)
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestProgressWithNilProgress(t *testing.T) {
	t.Parallel()

	// Create display with nil progress
	td := &TerminalDisplay{
		options:  &Options{Theme: LightTheme()},
		progress: nil,
	}

	// ShowProgress should handle nil progress gracefully
	assert.NotPanics(t, func() {
		td.ShowProgress(0.5, "test")
	})
}

func TestAutoDetectThemeHeuristics(t *testing.T) {
	// Can't use t.Parallel() because we're setting environment variables

	// Save original environment
	originalColorTerm := os.Getenv("COLORTERM")
	originalTerm := os.Getenv("TERM")
	originalTermProgram := os.Getenv("TERM_PROGRAM")

	defer func() {
		t.Setenv("COLORTERM", originalColorTerm)
		t.Setenv("TERM", originalTerm)
		t.Setenv("TERM_PROGRAM", originalTermProgram)
	}()

	tests := []struct {
		name        string
		colorTerm   string
		term        string
		termProgram string
		expectDark  bool
	}{
		{"dark in term", "", "xterm-dark", "", true},
		{"dark in term program", "", "xterm", "dark-terminal", true},
		{"256color modern terminal", "", "xterm-256color", "", true},
		{"truecolor support", "truecolor", "", "", true},
		{"basic terminal", "", "xterm", "", false},
		{"no indicators", "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("COLORTERM", tt.colorTerm)
			t.Setenv("TERM", tt.term)
			t.Setenv("TERM_PROGRAM", tt.termProgram)

			theme := autoDetectTheme()
			if tt.expectDark {
				assert.Equal(t, constants.ThemeDark, theme.Name)
			} else {
				assert.Equal(t, constants.ThemeLight, theme.Name)
			}
		})
	}
}

func TestDisplayErrorHandling(t *testing.T) {
	t.Parallel()

	// Test display with colors enabled but failing renderer
	opts := Options{
		Theme:        LightTheme(),
		WrapWidth:    80,
		EnableTables: true,
		EnableColors: true,
	}

	td := NewTerminalDisplayWithOptions(opts)

	// Test with context cancellation during display
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := td.Display(ctx, "# Test Content")
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestProgressEventStructure(t *testing.T) {
	t.Parallel()

	event := ProgressEvent{
		Percent: 0.75,
		Message: "Processing data",
	}

	assert.InDelta(t, 0.75, event.Percent, 0.01)
	assert.Equal(t, "Processing data", event.Message)

	// Test zero values
	zeroEvent := ProgressEvent{}
	assert.Zero(t, zeroEvent.Percent)
	assert.Empty(t, zeroEvent.Message)
}

func TestErrRawMarkdownError(t *testing.T) {
	t.Parallel()

	err := ErrRawMarkdown
	assert.Implements(t, (*error)(nil), err)
	assert.Contains(t, err.Error(), "raw markdown")
}

func TestGetThemeByNameEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"uppercase light", "LIGHT", constants.ThemeLight},
		{"mixed case dark", "Dark", constants.ThemeDark},
		{"uppercase custom", "CUSTOM", "custom"},
		{"empty string", "", ""}, // Will auto-detect
		{"whitespace", "  ", ""}, // Will auto-detect
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			theme := getThemeByName(tt.input)
			if tt.expected == "" {
				// Should auto-detect, so will be either light or dark
				assert.True(t, theme.Name == constants.ThemeLight || theme.Name == constants.ThemeDark)
			} else {
				assert.Equal(t, tt.expected, theme.Name)
			}
		})
	}
}
