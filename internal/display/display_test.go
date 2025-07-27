package display

import (
	"os"
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
