// Package display provides functions for styled terminal output.
package display

import (
	"context"
	"fmt"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle(). //nolint:gochecknoglobals // UI styling
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	errorStyle = lipgloss.NewStyle(). //nolint:gochecknoglobals // UI styling
			Bold(true).
			Foreground(lipgloss.Color("#FF0000"))
)

const (
	// DefaultWordWrapWidth is the default word wrap width for terminal display.
	DefaultWordWrapWidth = 120
)

// Title prints the given string to the console using the predefined title style.
func Title(s string) {
	fmt.Println(titleStyle.Render(s))
}

// Error prints the input string to the terminal using a bold red error style.
func Error(s string) {
	fmt.Println(errorStyle.Render(s))
}

// TerminalDisplay represents a terminal markdown displayer.
type TerminalDisplay struct {
	renderer *glamour.TermRenderer
}

// NewTerminalDisplay returns a TerminalDisplay instance with a Glamour renderer configured for terminal display with proper fallbacks.
func NewTerminalDisplay() *TerminalDisplay {
	renderer, err := glamour.NewTermRenderer()
	if err != nil {
		return &TerminalDisplay{renderer: nil}
	}
	return &TerminalDisplay{renderer: renderer}
}

// Display renders and displays markdown content in the terminal with syntax highlighting.
func (td *TerminalDisplay) Display(_ context.Context, markdown string) error {
	// Handle fallback case where renderer is nil
	if td.renderer == nil {
		// Just print the markdown as-is without rendering
		fmt.Print(markdown)
		return nil
	}

	out, err := td.renderer.Render(markdown)
	if err != nil {
		return fmt.Errorf("failed to render markdown: %w", err)
	}

	fmt.Print(out)
	return nil
}
