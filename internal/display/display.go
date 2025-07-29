// Package display provides functions for styled terminal output.
package display

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/unclesp1d3r/opnFocus/internal/constants"
	"github.com/unclesp1d3r/opnFocus/internal/markdown"
)

// Theme and terminal color constants used throughout the display package.
const (
	Light     = "light"
	Dark      = "dark"
	None      = "none"
	Custom    = "custom"
	Auto      = "auto"
	Notty     = "notty"
	Truecolor = "truecolor"
	Bit24     = "24bit"
)

// ErrRawMarkdown is a sentinel error indicating that raw markdown should be displayed.
var ErrRawMarkdown = errors.New("raw markdown display requested")

// StyleSheet holds styles for various terminal display elements.
type StyleSheet struct {
	Title    lipgloss.Style
	Subtitle lipgloss.Style
	Table    lipgloss.Style
	Error    lipgloss.Style
	Warning  lipgloss.Style
	theme    Theme
}

// NewStyleSheet creates a new StyleSheet with the auto-detected theme.
func NewStyleSheet() *StyleSheet {
	// Use auto-detected theme
	theme := DetectTheme("")
	return NewStyleSheetWithTheme(theme)
}

// NewStyleSheetWithTheme creates a new StyleSheet with a specified theme.
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

// TitlePrint prints a title-styled text on the terminal.
func (s *StyleSheet) TitlePrint(text string) {
	fmt.Println(s.Title.Render(text))
}

// ErrorPrint prints an error-styled text on the terminal.
func (s *StyleSheet) ErrorPrint(text string) {
	fmt.Println(s.Error.Render(text))
}

// WarningPrint prints a warning-styled text on the terminal.
func (s *StyleSheet) WarningPrint(text string) {
	fmt.Println(s.Warning.Render(text))
}

// SubtitlePrint prints a subtitle-styled text on the terminal.
func (s *StyleSheet) SubtitlePrint(text string) {
	fmt.Println(s.Subtitle.Render(text))
}

// TablePrint prints a table-styled text on the terminal.
func (s *StyleSheet) TablePrint(text string) {
	fmt.Println(s.Table.Render(text))
}

// Global stylesheet instance for backward compatibility.
var globalStyleSheet = NewStyleSheet() //nolint:gochecknoglobals // Global UI styling

// Options holds display configuration settings.
type Options struct {
	Theme        Theme
	WrapWidth    int
	EnableTables bool
	EnableColors bool
}

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
		theme = LightTheme()
	case markdown.ThemeDark:
		theme = DarkTheme()
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

	// Determine theme for Glamour with proper fallback logic
	glamourStyle := DetermineGlamourStyle(opts)

	// Build Glamour options
	glamourOpts := []glamour.TermRendererOption{
		glamour.WithStandardStyle(glamourStyle),
	}

	// Add word wrap if specified
	if opts.WrapWidth > 0 {
		glamourOpts = append(glamourOpts, glamour.WithWordWrap(opts.WrapWidth))
	}

	// Skip Glamour rendering if colors are disabled
	if !opts.EnableColors {
		// Return sentinel error to indicate raw markdown should be used
		return nil, ErrRawMarkdown
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

// DetermineGlamourStyle determines the appropriate Glamour style based on theme and terminal capabilities.
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
		return Light
	case constants.ThemeDark:
		return Dark
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

// IsTerminalColorCapable checks if the terminal supports color output.
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

// isTerminal checks if the current environment is a terminal.
func isTerminal() bool {
	// Check if stdout is a terminal
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}

	// Check if it's a character device (terminal)
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
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
	options    *Options
	progress   *progress.Model
	progressMu sync.Mutex
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
	td.progressMu.Lock()
	defer td.progressMu.Unlock()

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
	td.progressMu.Lock()
	defer td.progressMu.Unlock()

	fmt.Print("\r\033[K") // Clear the current line
}

// Display renders and displays markdown content in the terminal with syntax highlighting.
func (td *TerminalDisplay) Display(_ context.Context, markdownContent string) error {
	// Get singleton renderer with current options
	renderer, err := getGlamourRenderer(td.options)
	if err != nil {
		// Check if this is our sentinel error for raw markdown
		if errors.Is(err, ErrRawMarkdown) {
			fmt.Print(markdownContent)
			return nil
		}
		// Fallback: print raw markdown if renderer creation fails
		fmt.Print(markdownContent)
		return fmt.Errorf("failed to create renderer, displaying raw markdown: %w", err)
	}

	// Render markdown with Glamour
	out, err := renderer.Render(markdownContent)
	if err != nil {
		return fmt.Errorf("failed to render markdown: %w", err)
	}

	fmt.Print(out)

	// Add navigation hints placeholder for future paging support
	if td.shouldShowNavigationHints() {
		td.showNavigationHints()
	}

	return nil
}

// DisplayWithProgress renders and displays markdown content with progress events.
func (td *TerminalDisplay) DisplayWithProgress(_ context.Context, markdownContent string, progressCh <-chan ProgressEvent) error {
	// Show initial progress
	td.ShowProgress(0.0, "Starting display...")

	// Use WaitGroup to synchronize with the progress goroutine
	var wg sync.WaitGroup
	wg.Add(1)

	// Listen for progress events in a goroutine
	go func() {
		defer wg.Done()
		for event := range progressCh {
			td.ShowProgress(event.Percent, event.Message)
		}
	}()

	// Simulate progress during rendering
	td.ShowProgress(constants.ProgressRenderingMarkdown, "Rendering markdown...")

	// Get singleton renderer with current options
	renderer, err := getGlamourRenderer(td.options)
	if err != nil {
		// Check if this is our sentinel error for raw markdown
		if errors.Is(err, ErrRawMarkdown) {
			td.ShowProgress(1.0, "Displaying raw markdown...")
			td.ClearProgress()
			fmt.Print(markdownContent)
			// Wait for progress goroutine to finish before returning
			wg.Wait()
			return nil
		}
		td.ShowProgress(1.0, "Displaying raw markdown...")
		td.ClearProgress()
		// Fallback: print raw markdown if renderer creation fails
		fmt.Print(markdownContent)
		// Wait for progress goroutine to finish before returning
		wg.Wait()
		return fmt.Errorf("failed to create renderer, displaying raw markdown: %w", err)
	}

	// Render markdown with Glamour
	out, err := renderer.Render(markdownContent)
	if err != nil {
		td.ClearProgress()
		// Wait for progress goroutine to finish before returning
		wg.Wait()
		return fmt.Errorf("failed to render markdown: %w", err)
	}

	td.ShowProgress(1.0, "Display complete!")
	td.ClearProgress()

	fmt.Print(out)

	// Add navigation hints placeholder for future paging support
	if td.shouldShowNavigationHints() {
		td.showNavigationHints()
	}

	// Wait for progress goroutine to finish before returning
	wg.Wait()

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
