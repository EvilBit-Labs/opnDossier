// Package display provides functions for styled terminal output and theme management.
package display

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/unclesp1d3r/opnFocus/internal/constants"
)

// Theme represents a color theme with customizable palettes.
type Theme struct {
	Name         string
	Palette      map[string]string
	GlamourStyle string
}

// LightTheme returns a Theme configured with a predefined light color palette and the Glamour style "light".
func LightTheme() Theme {
	return Theme{
		Name: "light",
		Palette: map[string]string{
			"background":   "#FFFFFF",
			"foreground":   "#000000",
			"primary":      "#007ACC",
			"secondary":    "#6B73FF",
			"accent":       "#FF6B6B",
			"muted":        "#6C757D",
			"success":      "#28A745",
			"warning":      "#FFC107",
			"error":        "#DC3545",
			"info":         "#17A2B8",
			"border":       "#DEE2E6",
			"highlight":    "#FFF3CD",
			"title":        "#495057",
			"subtitle":     "#6C757D",
			"table_header": "#E9ECEF",
			"table_border": "#DEE2E6",
		},
		GlamourStyle: "light",
	}
}

// DarkTheme returns a Theme configured with a predefined dark color palette and the Glamour style "dark".
func DarkTheme() Theme {
	return Theme{
		Name: "dark",
		Palette: map[string]string{
			"background":   "#1E1E1E",
			"foreground":   "#FFFFFF",
			"primary":      "#4FC3F7",
			"secondary":    "#BA68C8",
			"accent":       "#FF5722",
			"muted":        "#9E9E9E",
			"success":      "#4CAF50",
			"warning":      "#FF9800",
			"error":        "#F44336",
			"info":         "#2196F3",
			"border":       "#424242",
			"highlight":    "#333333",
			"title":        "#E0E0E0",
			"subtitle":     "#B0B0B0",
			"table_header": "#2D2D2D",
			"table_border": "#424242",
		},
		GlamourStyle: "dark",
	}
}

// CustomTheme returns a Theme with an empty palette and Glamour style set to "auto", intended for user customization.
func CustomTheme() Theme {
	return Theme{
		Name:         "custom",
		Palette:      map[string]string{},
		GlamourStyle: "auto",
	}
}

// DetectTheme determines the theme based on configuration and environment.
// DetectTheme determines the terminal color theme to use based on the provided configuration, the OPNFOCUS_THEME environment variable, or automatic detection if neither is set.
func DetectTheme(configTheme string) Theme {
	// Check if theme is explicitly set in config
	if configTheme != "" {
		return getThemeByName(configTheme)
	}

	// Check OPNFOCUS_THEME environment variable
	envTheme := os.Getenv("OPNFOCUS_THEME")
	if envTheme != "" {
		return getThemeByName(envTheme)
	}

	// Auto-detect theme based on environment
	return autoDetectTheme()
}

// getThemeByName returns a Theme matching the provided name ("light", "dark", or "custom").
// If the name is unrecognized, it falls back to automatic theme detection.
func getThemeByName(name string) Theme {
	switch strings.ToLower(name) {
	case "light":
		return LightTheme()
	case constants.ThemeDark:
		return DarkTheme()
	case "custom":
		return CustomTheme()
	default:
		return autoDetectTheme()
	}
}

// autoDetectTheme selects a terminal color theme by analyzing environment variables and terminal capabilities.
// It returns a dark theme if indicators such as 24-bit color support or dark-related terminal names are detected; otherwise, it defaults to a light theme.
func autoDetectTheme() Theme {
	// Check common terminal environment variables that indicate dark mode preference
	colorTerm := os.Getenv("COLORTERM")
	term := os.Getenv("TERM")

	// Check if terminal supports 24-bit color
	hasFullColorSupport := colorTerm == "truecolor" || colorTerm == "24bit"

	// Check for common dark terminal indicators
	isDarkTerminal := strings.Contains(term, "dark") ||
		strings.Contains(strings.ToLower(os.Getenv("TERM_PROGRAM")), "dark") ||
		hasFullColorSupport // Modern terminals often default to dark themes

	// Use Glamour's detection as a fallback for determining if dark theme is appropriate
	if isDarkTerminal {
		return DarkTheme()
	}

	// Additional heuristics: check terminal color count
	if strings.Contains(term, "256color") || hasFullColorSupport {
		return DarkTheme() // Modern terminals tend to use dark themes
	}

	// Default to light theme for basic terminals or when unsure
	return LightTheme()
}

// ApplyTheme applies the theme colors to a lipgloss style.
func (t *Theme) ApplyTheme(style lipgloss.Style, colorKey string) lipgloss.Style {
	if color, exists := t.Palette[colorKey]; exists {
		return style.Foreground(lipgloss.Color(color))
	}
	return style
}

// GetColor returns a color from the theme palette.
func (t *Theme) GetColor(colorKey string) string {
	if color, exists := t.Palette[colorKey]; exists {
		return color
	}
	// Return a default color if key not found
	if t.Name == "dark" {
		return "#FFFFFF" // White for dark theme
	}
	return "#000000" // Black for light theme
}

// IsLight returns true if the theme is a light theme.
func (t *Theme) IsLight() bool {
	return t.Name == "light"
}

// IsDark returns true if the theme is a dark theme.
func (t *Theme) IsDark() bool {
	return t.Name == "dark"
}

// GetGlamourStyleName returns the Glamour style name for this theme.
func (t *Theme) GetGlamourStyleName() string {
	return t.GlamourStyle
}
