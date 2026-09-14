// Package display provides functions for styled terminal output.
package display

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
)

// Theme and terminal color constants used throughout the display package.
const (
	// None disables all terminal styling.
	None = "none"
	// Custom indicates a custom color profile is in use.
	Custom = "custom"
	// Auto enables automatic color profile detection.
	Auto = "auto"
	// Notty indicates no TTY is available (non-interactive mode).
	Notty = "notty"
	// Truecolor indicates a terminal supporting 24-bit true color.
	Truecolor = "truecolor"
	// Bit24 is an alias for 24-bit color support.
	Bit24 = "24bit"
)

// Terminal display layout constants.
const (
	// DefaultWordWrapWidth is the default word wrap width for terminal display.
	DefaultWordWrapWidth = 120
)

// Options holds display configuration settings.
type Options struct {
	Theme        Theme
	WrapWidth    int
	EnableTables bool
	EnableColors bool
}

// convertMarkdownOptions creates a display.Options struct from the provided markdown.Options, mapping theme and display settings accordingly.
func convertMarkdownOptions(mdOpts converter.Options) Options {
	// Convert theme
	var theme Theme
	switch mdOpts.Theme {
	case converter.ThemeLight:
		theme = LightTheme()
	case converter.ThemeDark:
		theme = DarkTheme()
	case converter.ThemeAuto:
		theme = DetectTheme("")
	case converter.ThemeNone:
		theme = DetectTheme("") // Use detected theme but disable colors elsewhere
	default:
		theme = DetectTheme("")
	}

	return Options{
		Theme:        theme,
		WrapWidth:    mdOpts.WrapWidth,
		EnableTables: mdOpts.EnableTables,
		EnableColors: mdOpts.EnableColors,
	}
}

// DetermineGlamourStyle returns the Glamour style string to use for markdown rendering based on the provided options, considering color enablement, terminal color support, and the selected theme.
func DetermineGlamourStyle(opts *Options) string {
	// Check if colors are disabled first
	if !opts.EnableColors {
		return Notty
	}

	// Check terminal color capabilities
	if !IsTerminalColorCapable() {
		return "ascii"
	}

	// Determine theme-based style
	switch opts.Theme.Name {
	case constants.ThemeLight:
		return constants.ThemeLight
	case constants.ThemeDark:
		return constants.ThemeDark
	case "none":
		return Notty
	case "custom":
		// Custom theme uses auto-detection
		return Auto
	default: // "auto" or other
		// Use the theme's Glamour style name, which should handle auto-detection
		return opts.Theme.GetGlamourStyleName()
	}
}

// IsTerminalColorCapable returns true if the current terminal environment supports color output, based on environment variables and terminal type heuristics.
func IsTerminalColorCapable() bool {
	// Check if we're in a terminal
	if !isTerminal() {
		return false
	}

	// Check for color support indicators
	colorTerm := os.Getenv("COLORTERM")
	term := os.Getenv("TERM")

	// Check for explicit color support
	if colorTerm == Truecolor || colorTerm == Bit24 {
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

// isTerminal returns true if the standard output is a terminal device.
func isTerminal() bool {
	// Check if stdout is a terminal
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}

	// Check if it's a character device (terminal)
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// TerminalDisplay represents a terminal markdown displayer.
type TerminalDisplay struct {
	options     *Options
	renderer    *glamour.TermRenderer
	rendererErr error // Preserved from construction; nil if colors were intentionally disabled
}

// NewTerminalDisplayWithOptions returns a TerminalDisplay configured with the provided options, setting the wrap width if not specified.
func NewTerminalDisplayWithOptions(opts Options) *TerminalDisplay {
	// Set default wrap width if not specified (-1 or negative values)
	// Preserve 0 (no wrapping) and positive values (explicit width)
	if opts.WrapWidth < 0 {
		opts.WrapWidth = getTerminalWidth()
	}

	// Build per-instance Glamour renderer
	var renderer *glamour.TermRenderer
	var rendererErr error
	if opts.EnableColors {
		glamourStyle := DetermineGlamourStyle(&opts)
		glamourOpts := []glamour.TermRendererOption{
			glamour.WithStandardStyle(glamourStyle),
		}
		if opts.WrapWidth > 0 {
			glamourOpts = append(glamourOpts, glamour.WithWordWrap(opts.WrapWidth))
		}
		r, err := glamour.NewTermRenderer(glamourOpts...)
		if err != nil {
			rendererErr = err
		} else {
			renderer = r
		}
	}

	return &TerminalDisplay{
		options:     &opts,
		renderer:    renderer,
		rendererErr: rendererErr,
	}
}

// NewTerminalDisplayWithMarkdownOptions creates a TerminalDisplay with markdown options.
// This provides compatibility with the markdown package options.
func NewTerminalDisplayWithMarkdownOptions(mdOpts converter.Options) *TerminalDisplay {
	return NewTerminalDisplayWithOptions(convertMarkdownOptions(mdOpts))
}

// getTerminalWidth returns the terminal width in columns, using the COLUMNS environment variable if set, or a default wrap width otherwise.
func getTerminalWidth() int {
	columns := os.Getenv("COLUMNS")
	if columns != "" {
		if width, err := strconv.Atoi(columns); err == nil {
			return width
		}
	}

	return DefaultWordWrapWidth
}

// Display renders and displays markdown content in the terminal with syntax highlighting.
func (td *TerminalDisplay) Display(ctx context.Context, markdownContent string) error {
	// Check for context cancellation before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	markdownContent = wrapMarkdownContent(markdownContent, td.options.WrapWidth)

	// Check if renderer is available (nil when colors disabled or creation failed)
	if td.renderer == nil {
		if td.rendererErr != nil {
			fmt.Fprintf(os.Stderr, "Note: Displaying raw markdown due to renderer error: %v\n", td.rendererErr)
		}
		fmt.Print(wrapRenderedOutput(markdownContent, td.options.WrapWidth))
		return nil
	}

	// Check for context cancellation before rendering
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Render markdown with Glamour — fallback to raw output on failure
	out, err := td.renderer.Render(markdownContent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to render markdown (error: %v), displaying raw output\n", err)
		fmt.Print(wrapRenderedOutput(markdownContent, td.options.WrapWidth))
		return nil
	}

	// Check for context cancellation before output
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	fmt.Print(wrapRenderedOutput(out, td.options.WrapWidth))

	// Add navigation hints placeholder for future paging support
	if td.shouldShowNavigationHints() {
		td.showNavigationHints()
	}

	return nil
}

// shouldShowNavigationHints determines if navigation hints should be displayed.
// This is a placeholder for future paging functionality.
func (td *TerminalDisplay) shouldShowNavigationHints() bool {
	// TODO: Implement paging detection logic
	// For now, return false as paging is not yet implemented
	return false
}

// showNavigationHints displays navigation shortcuts for paging.
// This is a placeholder for future paging functionality.
func (td *TerminalDisplay) showNavigationHints() {
	// TODO: Implement navigation hints display
	// Example: "↑/↓ to scroll, q to quit, h for help"
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#888888")).
		Italic(true).
		MarginTop(1)

	hints := "Navigation: ↑/↓ to scroll, q to quit, h for help"
	fmt.Println(style.Render(hints))
}
