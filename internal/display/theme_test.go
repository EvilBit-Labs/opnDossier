package display_test

import (
	"os"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/display"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDetectTheme tests theme detection with various environment configurations.
func TestDetectTheme(t *testing.T) {
	// Save original environment variables
	originalColorTerm := os.Getenv("COLORTERM")
	originalTerm := os.Getenv("TERM")
	originalTheme := os.Getenv("OPNDOSSIER_THEME")
	originalTermProgram := os.Getenv("TERM_PROGRAM")

	// Restore environment after tests
	defer func() {
		t.Setenv("COLORTERM", originalColorTerm)
		t.Setenv("TERM", originalTerm)
		t.Setenv("OPNDOSSIER_THEME", originalTheme)
		t.Setenv("TERM_PROGRAM", originalTermProgram)
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
		{"Config overrides all", "light", "dark", "truecolor", "xterm-256color", "", "light"},
		{"Config dark theme", "dark", "", "", "", "", "dark"},
		{"Config custom theme", "custom", "", "", "", "", "custom"},

		// Environment variable takes second priority
		{"Env theme override", "", "dark", "", "xterm", "", "dark"},
		{"Env light theme", "", "light", "truecolor", "xterm-256color", "", "light"},

		// Auto-detection based on terminal capabilities
		{"Truecolor detection", "", "", "truecolor", "xterm-256color", "", "dark"},
		{"24bit color detection", "", "", "24bit", "xterm", "", "dark"},
		{"256color detection", "", "", "", "xterm-256color", "", "dark"},
		{"Dark term detection", "", "", "", "xterm-dark", "", "dark"},
		{"Dark term program", "", "", "", "xterm", "dark-term", "dark"},

		// Default to light theme
		{"Basic terminal default", "", "", "", "xterm", "", "light"},
		{"No terminal info", "", "", "", "", "", "light"},

		// Invalid values default to auto-detection
		{"Invalid config theme", "invalid", "", "", "xterm", "", "light"},
		{"Invalid env theme", "", "invalid", "", "xterm", "", "light"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables for this test
			t.Setenv("OPNDOSSIER_THEME", tt.envTheme)
			t.Setenv("COLORTERM", tt.colorTerm)
			t.Setenv("TERM", tt.term)
			t.Setenv("TERM_PROGRAM", tt.termProgram)

			theme := display.DetectTheme(tt.configTheme)
			assert.Equal(t, tt.expected, theme.Name)
		})
	}
}

// TestThemeProperties tests the properties and methods of Theme struct.
func TestThemeProperties(t *testing.T) {
	tests := []struct {
		name        string
		theme       display.Theme
		isLight     bool
		isDark      bool
		colorExists bool
		colorKey    string
	}{
		{"Light theme properties", display.LightTheme(), true, false, true, "background"},
		{"Dark theme properties", display.DarkTheme(), false, true, true, "foreground"},
		{"Custom theme properties", display.CustomTheme(), false, false, false, "nonexistent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isLight, tt.theme.IsLight())
			assert.Equal(t, tt.isDark, tt.theme.IsDark())

			if tt.colorExists {
				color := tt.theme.GetColor(tt.colorKey)
				assert.NotEmpty(t, color)
				assert.Equal(t, byte('#'), color[0]) // Should be a hex color
			}

			// Test Glamour style name
			styleName := tt.theme.GetGlamourStyleName()
			assert.NotEmpty(t, styleName)
		})
	}
}

// TestThemeColorPalette tests the color palette functionality.
func TestThemeColorPalette(t *testing.T) {
	t.Run("Light theme palette", func(t *testing.T) {
		theme := display.LightTheme()

		// Test that key colors exist
		requiredColors := []string{"background", "foreground", "primary", "error", "warning", "success"}
		for _, colorKey := range requiredColors {
			color := theme.GetColor(colorKey)
			assert.NotEmpty(t, color, "Color %s should exist in light theme", colorKey)
			assert.Equal(t, byte('#'), color[0], "Color %s should be a hex color", colorKey)
		}
	})

	t.Run("Dark theme palette", func(t *testing.T) {
		theme := display.DarkTheme()

		// Test that key colors exist
		requiredColors := []string{"background", "foreground", "primary", "error", "warning", "success"}
		for _, colorKey := range requiredColors {
			color := theme.GetColor(colorKey)
			assert.NotEmpty(t, color, "Color %s should exist in dark theme", colorKey)
			assert.Equal(t, byte('#'), color[0], "Color %s should be a hex color", colorKey)
		}
	})

	t.Run("Nonexistent color fallback", func(t *testing.T) {
		lightTheme := display.LightTheme()
		darkTheme := display.DarkTheme()

		// Test fallback for nonexistent colors
		lightFallback := lightTheme.GetColor("nonexistent")
		darkFallback := darkTheme.GetColor("nonexistent")

		assert.Equal(t, "#000000", lightFallback) // Black for light theme
		assert.Equal(t, "#FFFFFF", darkFallback)  // White for dark theme
	})
}

// TestStyleSheetCreation tests the creation of StyleSheet with themes.
func TestStyleSheetCreation(t *testing.T) {
	t.Run("Default stylesheet creation", func(t *testing.T) {
		stylesheet := display.NewStyleSheet()
		require.NotNil(t, stylesheet)
	})

	t.Run("Themed stylesheet creation", func(t *testing.T) {
		themes := []display.Theme{display.LightTheme(), display.DarkTheme(), display.CustomTheme()}

		for _, theme := range themes {
			stylesheet := display.NewStyleSheetWithTheme(theme)
			require.NotNil(t, stylesheet, "Stylesheet should be created for theme %s", theme.Name)
		}
	})
}

// TestTerminalDisplayCreation tests the creation of TerminalDisplay with themes.
func TestTerminalDisplayCreation(t *testing.T) {
	t.Run("Default terminal display creation", func(t *testing.T) {
		terminalDisplay := display.NewTerminalDisplay()
		require.NotNil(t, terminalDisplay)
	})

	t.Run("Themed terminal display creation", func(t *testing.T) {
		themes := []display.Theme{display.LightTheme(), display.DarkTheme(), display.CustomTheme()}

		for _, theme := range themes {
			terminalDisplay := display.NewTerminalDisplayWithTheme(theme)
			require.NotNil(t, terminalDisplay, "TerminalDisplay should be created for theme %s", theme.Name)
		}
	})
}
