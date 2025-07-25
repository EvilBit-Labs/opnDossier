// Package display provides functions for styled terminal output.
package display

import (
	"fmt"

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
