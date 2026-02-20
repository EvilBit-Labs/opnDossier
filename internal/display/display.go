// Package display provides functions for styled terminal output.
package display

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/charmbracelet/bubbles/progress"
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

// StyleSheet holds styles for various terminal display elements.
type StyleSheet struct {
	Title    lipgloss.Style
	Subtitle lipgloss.Style
	Table    lipgloss.Style
	Error    lipgloss.Style
	Warning  lipgloss.Style
	theme    Theme
}

// NewStyleSheet returns a new StyleSheet configured with an automatically detected theme based on the current environment.
func NewStyleSheet() *StyleSheet {
	// Use auto-detected theme
	theme := DetectTheme("")
	return NewStyleSheetWithTheme(theme)
}

// NewStyleSheetWithTheme returns a new StyleSheet configured with the provided theme.
// The StyleSheet includes styled elements for titles, subtitles, tables, errors, and warnings, using colors from the specified theme.
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

// Options holds display configuration settings.
type Options struct {
	Theme        Theme
	WrapWidth    int
	EnableTables bool
	EnableColors bool
}

// DefaultOptions returns an Options struct with the default theme, word wrap width, and both tables and colors enabled.
func DefaultOptions() Options {
	return Options{
		Theme:        DetectTheme(""),
		WrapWidth:    DefaultWordWrapWidth,
		EnableTables: true,
		EnableColors: true,
	}
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
	progress    *progress.Model
	progressMu  sync.Mutex
}

// NewTerminalDisplay creates a TerminalDisplay with default display options and progress bar settings.
func NewTerminalDisplay() *TerminalDisplay {
	return NewTerminalDisplayWithOptions(DefaultOptions())
}

// NewTerminalDisplayWithTheme creates a TerminalDisplay with the specified theme.
// NewTerminalDisplayWithTheme creates a TerminalDisplay with the specified theme and terminal width.
//
// Deprecated: Use NewTerminalDisplayWithOptions instead.
func NewTerminalDisplayWithTheme(theme Theme) *TerminalDisplay {
	opts := DefaultOptions()
	opts.Theme = theme
	opts.WrapWidth = getTerminalWidth()

	return NewTerminalDisplayWithOptions(opts)
}

// NewTerminalDisplayWithOptions returns a TerminalDisplay configured with the provided options, initializing the progress bar with theme-based colors and setting the wrap width if not specified.
func NewTerminalDisplayWithOptions(opts Options) *TerminalDisplay {
	// Set default wrap width if not specified (-1 or negative values)
	// Preserve 0 (no wrapping) and positive values (explicit width)
	if opts.WrapWidth < 0 {
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
			fmt.Fprintf(os.Stderr, "Warning: Failed to create markdown renderer: %v\n", err)
			rendererErr = err
		} else {
			renderer = r
		}
	}

	return &TerminalDisplay{
		options:     &opts,
		renderer:    renderer,
		rendererErr: rendererErr,
		progress:    &p,
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

// DisplayWithProgress renders and displays markdown content with progress events.
func (td *TerminalDisplay) DisplayWithProgress(
	ctx context.Context,
	markdownContent string,
	progressCh <-chan ProgressEvent,
) error {
	// Check for context cancellation before starting
	if err := td.checkContext(ctx); err != nil {
		return err
	}

	// Show initial progress
	td.ShowProgress(0.0, "Starting display...")

	// Setup progress handling goroutine
	wg, _ := td.setupProgressHandling(ctx, progressCh)

	// Check context cancellation before rendering
	if err := td.checkContext(ctx); err != nil {
		wg.Wait()
		return err
	}

	// Simulate progress during rendering
	td.ShowProgress(constants.ProgressRenderingMarkdown, "Rendering markdown...")

	// Render content
	err := td.renderContent(ctx, markdownContent, wg)

	// Wait for progress goroutine to finish before returning
	wg.Wait()

	return err
}

// checkContext checks and handles context cancellation.
func (td *TerminalDisplay) checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// setupProgressHandling sets up a goroutine for handling progress events.
//
//nolint:gocritic // Named returns not needed for this function
func (td *TerminalDisplay) setupProgressHandling(
	ctx context.Context,
	progressCh <-chan ProgressEvent,
) (*sync.WaitGroup, chan struct{}) {
	var waitGroup sync.WaitGroup
	waitGroup.Add(1)

	done := make(chan struct{})

	go func() {
		defer waitGroup.Done()
		defer close(done)

		for {
			select {
			case event, ok := <-progressCh:
				if !ok {
					return
				}
				// Check context before updating progress
				if err := td.checkContext(ctx); err != nil {
					return
				}
				td.ShowProgress(event.Percent, event.Message)
			case <-ctx.Done():
				return
			}
		}
	}()

	return &waitGroup, done
}

// renderContent handles rendering the markdown content and manages progress.
func (td *TerminalDisplay) renderContent(ctx context.Context, markdownContent string, wg *sync.WaitGroup) error {
	markdownContent = wrapMarkdownContent(markdownContent, td.options.WrapWidth)

	// Check if renderer is available (nil when colors disabled or creation failed)
	if td.renderer == nil {
		if td.rendererErr != nil {
			td.ShowProgress(1.0, "Displaying raw markdown (renderer error)...")
			fmt.Fprintf(os.Stderr, "Note: Displaying raw markdown due to renderer error: %v\n", td.rendererErr)
		} else {
			td.ShowProgress(1.0, "Displaying raw markdown (colors disabled)...")
		}
		td.ClearProgress()
		fmt.Print(wrapRenderedOutput(markdownContent, td.options.WrapWidth))
		wg.Wait()
		return nil
	}

	// Check for context cancellation before rendering
	if err := td.checkContext(ctx); err != nil {
		wg.Wait()
		return err
	}

	// Render markdown with Glamour
	out, err := td.renderer.Render(markdownContent)
	if err != nil {
		return td.handleRendererError(err, markdownContent, wg)
	}

	// Check for context cancellation before output
	if err := td.checkContext(ctx); err != nil {
		wg.Wait()
		return err
	}

	td.ShowProgress(1.0, "Display complete!")
	td.ClearProgress()

	fmt.Print(wrapRenderedOutput(out, td.options.WrapWidth))

	// Add navigation hints placeholder for future paging support
	if td.shouldShowNavigationHints() {
		td.showNavigationHints()
	}

	return nil
}

// handleRendererError handles unexpected render failures by falling back to raw markdown output.
func (td *TerminalDisplay) handleRendererError(err error, markdownContent string, wg *sync.WaitGroup) error {
	td.ShowProgress(1.0, "Renderer failed, displaying raw markdown...")
	td.ClearProgress()

	fmt.Fprintf(os.Stderr, "Warning: Failed to render markdown (error: %v), displaying raw output\n", err)
	fmt.Print(wrapRenderedOutput(markdownContent, td.options.WrapWidth))
	wg.Wait()

	// Return nil since we've handled the error by displaying raw markdown
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
