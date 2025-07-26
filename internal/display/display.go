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

// Title prints the given string to the console using the predefined title style.
func Title(s string) {
	fmt.Println(titleStyle.Render(s))
}

// Error prints the given string to the console using a bold red error style.
func Error(s string) {
	fmt.Println(errorStyle.Render(s))
}

// TerminalDisplay represents a terminal markdown displayer.
type TerminalDisplay struct {
	renderer *glamour.TermRenderer
}

// NewTerminalDisplay creates a new terminal display with glamour rendering.
func NewTerminalDisplay() *TerminalDisplay {
	// Create renderer with auto style detection (adapts to terminal theme)
	renderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(120),
	)
	if err != nil {
		// Fallback to default renderer if auto style fails
		renderer, _ = glamour.NewTermRenderer()
	}

	return &TerminalDisplay{
		renderer: renderer,
	}
}

// Display renders and displays markdown content in the terminal with syntax highlighting.
func (td *TerminalDisplay) Display(_ context.Context, markdown string) error {
	out, err := td.renderer.Render(markdown)
	if err != nil {
		return fmt.Errorf("failed to render markdown: %w", err)
	}

	fmt.Print(out)
	return nil
}
