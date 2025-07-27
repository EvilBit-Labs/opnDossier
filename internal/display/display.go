// Package display provides functions for styled terminal output.
package display

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/unclesp1d3r/opnFocus/internal/markdown"
)

type StyleSheet struct {
	Title    lipgloss.Style
	Subtitle lipgloss.Style
	Table    lipgloss.Style
	Error    lipgloss.Style
	Warning  lipgloss.Style
	theme    Theme
}

func NewStyleSheet() *StyleSheet {
	// Use auto-detected theme
	theme := DetectTheme("")
	return NewStyleSheetWithTheme(theme)
}

func NewStyleSheetWithTheme(theme Theme) *StyleSheet {
	return &StyleSheet{
		Title: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(theme.GetColor("title"))).
			Background(lipgloss.Color(theme.GetColor("primary"))).
			Padding(0, 1),
		Subtitle: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(theme.GetColor("subtitle"))).
			Padding(0, 1),
		Table: lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.GetColor("foreground"))).
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color(theme.GetColor("table_border"))),
		Error: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(theme.GetColor("error"))),
		Warning: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(theme.GetColor("warning"))),
		theme: theme,
	}
}

const (
	// DefaultWordWrapWidth is the default word wrap width for terminal display.
	DefaultWordWrapWidth = 120
)

func (s *StyleSheet) TitlePrint(text string) {
	fmt.Println(s.Title.Render(text))
}

func (s *StyleSheet) ErrorPrint(text string) {
	fmt.Println(s.Error.Render(text))
}

func (s *StyleSheet) WarningPrint(text string) {
	fmt.Println(s.Warning.Render(text))
}

func (s *StyleSheet) SubtitlePrint(text string) {
	fmt.Println(s.Subtitle.Render(text))
}

func (s *StyleSheet) TablePrint(text string) {
	fmt.Println(s.Table.Render(text))
}

// Global stylesheet instance for backward compatibility.
var globalStyleSheet = NewStyleSheet() //nolint:gochecknoglobals // Global UI styling

// Temporary local Options struct to avoid markdown package dependency issues.
type Options struct {
	Theme        Theme
	WrapWidth    int
	EnableTables bool
	EnableColors bool
}

// Temporary Theme enum.
type OptionsTheme string

const (
	ThemeAuto  OptionsTheme = "auto"
	ThemeLight OptionsTheme = "light"
	ThemeDark  OptionsTheme = "dark"
	ThemeNone  OptionsTheme = "none"
)

// DefaultOptions returns default options.
func DefaultOptions() Options {
	return Options{
		Theme:        DetectTheme(""),
		WrapWidth:    DefaultWordWrapWidth,
		EnableTables: true,
		EnableColors: true,
	}
}

// convertMarkdownOptions converts markdown.Options to display.Options.
func convertMarkdownOptions(mdOpts markdown.Options) Options {
	// Convert theme
	var theme Theme
	switch mdOpts.Theme {
	case markdown.ThemeLight:
		theme = LightTheme
	case markdown.ThemeDark:
		theme = DarkTheme
	default: // markdown.ThemeAuto or other
		theme = DetectTheme("")
	}

	return Options{
		Theme:        theme,
		WrapWidth:    mdOpts.WrapWidth,
		EnableTables: mdOpts.EnableTables,
		EnableColors: mdOpts.EnableColors,
	}
}

// Singleton Glamour renderer variables.
var (
	rendererMu   sync.RWMutex          //nolint:gochecknoglobals // Singleton pattern
	rendererOnce sync.Once             //nolint:gochecknoglobals // Singleton pattern
	rendererInst *glamour.TermRenderer //nolint:gochecknoglobals // Singleton instance
	rendererOpts *Options              //nolint:gochecknoglobals // Last used options
)

// getGlamourRenderer returns a singleton Glamour renderer configured with the given options.
// It creates a new renderer only if options have changed or none exists.
func getGlamourRenderer(opts *Options) (*glamour.TermRenderer, error) {
	rendererMu.RLock()
	// Check if we need to recreate the renderer
	needsRecreate := rendererInst == nil || rendererOpts == nil ||
		rendererOpts.Theme.Name != opts.Theme.Name ||
		rendererOpts.WrapWidth != opts.WrapWidth ||
		rendererOpts.EnableTables != opts.EnableTables ||
		rendererOpts.EnableColors != opts.EnableColors
	rendererMu.RUnlock()

	if !needsRecreate {
		rendererMu.RLock()
		defer rendererMu.RUnlock()
		return rendererInst, nil
	}

	rendererMu.Lock()
	defer rendererMu.Unlock()

	// Double-check pattern
	if rendererInst != nil && rendererOpts != nil &&
		rendererOpts.Theme.Name == opts.Theme.Name &&
		rendererOpts.WrapWidth == opts.WrapWidth &&
		rendererOpts.EnableTables == opts.EnableTables &&
		rendererOpts.EnableColors == opts.EnableColors {
		return rendererInst, nil
	}

	// Determine theme for Glamour
	var glamourStyle string
	switch opts.Theme.Name {
	case "light":
		glamourStyle = "light"
	case "dark":
		glamourStyle = "dark"
	case "none":
		glamourStyle = "notty"
	default: // "auto" or other
		glamourStyle = opts.Theme.GetGlamourStyleName()
	}

	// Build Glamour options
	glamourOpts := []glamour.TermRendererOption{
		glamour.WithStandardStyle(glamourStyle),
	}

	// Add word wrap if specified
	if opts.WrapWidth > 0 {
		glamourOpts = append(glamourOpts, glamour.WithWordWrap(opts.WrapWidth))
	}

	// Configure environment for consistent rendering
	if !opts.EnableColors {
		// Set TERM to dumb to disable colors as per user rules
		os.Setenv("TERM", "dumb")
		defer os.Unsetenv("TERM")
	}

	// Create new renderer with options
	renderer, err := glamour.NewTermRenderer(glamourOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Glamour renderer: %w", err)
	}

	// Store the new renderer and options
	rendererInst = renderer
	rendererOpts = &Options{
		Theme:        opts.Theme,
		WrapWidth:    opts.WrapWidth,
		EnableTables: opts.EnableTables,
		EnableColors: opts.EnableColors,
	}

	return renderer, nil
}

// Title prints the given string to the console using the predefined title style.
// Deprecated: Use StyleSheet.TitlePrint instead.
func Title(s string) {
	globalStyleSheet.TitlePrint(s)
}

// Error prints the input string to the terminal using a bold red error style.
// Deprecated: Use StyleSheet.ErrorPrint instead.
func Error(s string) {
	globalStyleSheet.ErrorPrint(s)
}

// TerminalDisplay represents a terminal markdown displayer.
type TerminalDisplay struct {
	options  *Options
	progress *progress.Model
}

// NewTerminalDisplay returns a TerminalDisplay instance with default options.
func NewTerminalDisplay() *TerminalDisplay {
	return NewTerminalDisplayWithOptions(DefaultOptions())
}

// NewTerminalDisplayWithTheme creates a TerminalDisplay with the specified theme.
// Deprecated: Use NewTerminalDisplayWithOptions instead.
func NewTerminalDisplayWithTheme(theme Theme) *TerminalDisplay {
	opts := DefaultOptions()
	opts.Theme = theme
	opts.WrapWidth = getTerminalWidth()
	return NewTerminalDisplayWithOptions(opts)
}

// NewTerminalDisplayWithOptions creates a TerminalDisplay with the specified options.
func NewTerminalDisplayWithOptions(opts Options) *TerminalDisplay {
	// Set default wrap width if not specified
	if opts.WrapWidth == 0 {
		opts.WrapWidth = getTerminalWidth()
	}

	// Use the theme from options for progress bar
	theme := opts.Theme

	progressColor1 := theme.GetColor("accent")
	progressColor2 := theme.GetColor("secondary")
	p := progress.New(
		progress.WithScaledGradient(progressColor1, progressColor2),
		progress.WithWidth(opts.WrapWidth),
	)

	return &TerminalDisplay{
		options:  &opts,
		progress: &p,
	}
}

// NewTerminalDisplayWithMarkdownOptions creates a TerminalDisplay with markdown options.
// This provides compatibility with the markdown package options.
func NewTerminalDisplayWithMarkdownOptions(mdOpts markdown.Options) *TerminalDisplay {
	return NewTerminalDisplayWithOptions(convertMarkdownOptions(mdOpts))
}

func getTerminalWidth() int {
	columns := os.Getenv("COLUMNS")
	if columns != "" {
		if width, err := strconv.Atoi(columns); err == nil {
			return width
		}
	}
	return DefaultWordWrapWidth
}

// ProgressEvent represents a progress update event.
type ProgressEvent struct {
	Percent float64
	Message string
}

// ShowProgress displays a progress bar with the given completion percentage and message.
func (td *TerminalDisplay) ShowProgress(percent float64, message string) {
	if td.progress == nil {
		return
	}
	cmd := td.progress.SetPercent(percent)
	if cmd != nil {
		// For a simple progress display, we would normally handle the command in a Bubble Tea program
		// For now, we'll just print the progress view
		fmt.Printf("\r%s %s", td.progress.View(), message)
	}
}

// ClearProgress clears the progress indicator from the terminal.
func (td *TerminalDisplay) ClearProgress() {
	fmt.Print("\r\033[K") // Clear the current line
}

// Display renders and displays markdown content in the terminal with syntax highlighting.
func (td *TerminalDisplay) Display(_ context.Context, markdownContent string) error {
	// Get singleton renderer with current options
	renderer, err := getGlamourRenderer(td.options)
	if err != nil {
		// Fallback: print raw markdown if renderer creation fails
		fmt.Print(markdownContent)
		return fmt.Errorf("failed to create renderer, displaying raw markdown: %w", err)
	}

	// Render markdown with Glamour
	out, err := renderer.Render(markdownContent)
	if err != nil {
		return fmt.Errorf("failed to render markdown: %w", err)
	}

	// Output rendered content (replaces direct fmt.Print)
	fmt.Print(out)

	// Add navigation hints placeholder for future paging support
	if td.shouldShowNavigationHints() {
		td.showNavigationHints()
	}

	return nil
}

// DisplayWithProgress renders and displays markdown content with progress events.
func (td *TerminalDisplay) DisplayWithProgress(ctx context.Context, markdownContent string, progressCh <-chan ProgressEvent) error {
	// Show initial progress
	td.ShowProgress(0.0, "Starting display...")

	// Listen for progress events in a goroutine
	go func() {
		for event := range progressCh {
			td.ShowProgress(event.Percent, event.Message)
		}
	}()

	// Simulate progress during rendering
	td.ShowProgress(0.5, "Rendering markdown...")

	// Get singleton renderer with current options
	renderer, err := getGlamourRenderer(td.options)
	if err != nil {
		td.ShowProgress(1.0, "Displaying raw markdown...")
		td.ClearProgress()
		// Fallback: print raw markdown if renderer creation fails
		fmt.Print(markdownContent)
		return fmt.Errorf("failed to create renderer, displaying raw markdown: %w", err)
	}

	// Render markdown with Glamour
	out, err := renderer.Render(markdownContent)
	if err != nil {
		td.ClearProgress()
		return fmt.Errorf("failed to render markdown: %w", err)
	}

	td.ShowProgress(1.0, "Display complete!")
	td.ClearProgress()

	// Output rendered content (replaces direct fmt.Print)
	fmt.Print(out)

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
