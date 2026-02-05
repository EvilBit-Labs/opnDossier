// Package formatters provides output formatting for diff results.
package formatters

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
	"github.com/charmbracelet/lipgloss"
)

// Terminal environment constants.
const (
	termEnvVar    = "TERM"
	noColorEnvVar = "NO_COLOR"
	termDumb      = "dumb"
)

// TerminalFormatter formats diff results for terminal output.
type TerminalFormatter struct {
	writer    io.Writer
	useStyles bool
	styles    terminalStyles
}

// terminalStyles holds lipgloss styles for terminal output.
type terminalStyles struct {
	added          lipgloss.Style
	removed        lipgloss.Style
	modified       lipgloss.Style
	sectionHeader  lipgloss.Style
	path           lipgloss.Style
	description    lipgloss.Style
	value          lipgloss.Style
	securityHigh   lipgloss.Style
	securityMedium lipgloss.Style
	securityLow    lipgloss.Style
	summary        lipgloss.Style
	noChanges      lipgloss.Style
}

// NewTerminalFormatter creates a new terminal formatter.
func NewTerminalFormatter(writer io.Writer) *TerminalFormatter {
	useStyles := shouldUseStyles()
	return &TerminalFormatter{
		writer:    writer,
		useStyles: useStyles,
		styles:    createStyles(useStyles),
	}
}

// shouldUseStyles determines if styled output should be used.
func shouldUseStyles() bool {
	return os.Getenv(termEnvVar) != termDumb && os.Getenv(noColorEnvVar) == ""
}

// createStyles creates the lipgloss styles for terminal output.
func createStyles(enabled bool) terminalStyles {
	if !enabled {
		return terminalStyles{}
	}

	return terminalStyles{
		added:          lipgloss.NewStyle().Foreground(lipgloss.Color("#4CAF50")).Bold(true),
		removed:        lipgloss.NewStyle().Foreground(lipgloss.Color("#F44336")).Bold(true),
		modified:       lipgloss.NewStyle().Foreground(lipgloss.Color("#FF9800")).Bold(true),
		sectionHeader:  lipgloss.NewStyle().Foreground(lipgloss.Color("#2196F3")).Bold(true).Underline(true),
		path:           lipgloss.NewStyle().Foreground(lipgloss.Color("#9E9E9E")),
		description:    lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")),
		value:          lipgloss.NewStyle().Foreground(lipgloss.Color("#B0B0B0")),
		securityHigh:   lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true),
		securityMedium: lipgloss.NewStyle().Foreground(lipgloss.Color("#FF9800")),
		securityLow:    lipgloss.NewStyle().Foreground(lipgloss.Color("#FFEB3B")),
		summary:        lipgloss.NewStyle().Bold(true),
		noChanges:      lipgloss.NewStyle().Foreground(lipgloss.Color("#4CAF50")).Italic(true),
	}
}

// Format formats the diff result for terminal output.
func (f *TerminalFormatter) Format(result *diff.Result) error {
	if !result.HasChanges() {
		return f.formatNoChanges()
	}

	// Print summary header
	if err := f.formatSummary(result); err != nil {
		return err
	}

	// Group changes by section
	bySection := result.ChangesBySection()

	// Get sorted section names for deterministic output
	sections := make([]diff.Section, 0, len(bySection))
	for section := range bySection {
		sections = append(sections, section)
	}
	sort.Slice(sections, func(i, j int) bool {
		return sections[i].String() < sections[j].String()
	})

	// Print each section
	for _, section := range sections {
		changes := bySection[section]
		if err := f.formatSection(section, changes); err != nil {
			return err
		}
	}

	return nil
}

// formatNoChanges prints a message when there are no changes.
func (f *TerminalFormatter) formatNoChanges() error {
	msg := "No changes detected between configurations."
	if f.useStyles {
		msg = f.styles.noChanges.Render(msg)
	}
	_, err := fmt.Fprintln(f.writer, msg)
	return err
}

// formatSummary prints the summary header.
func (f *TerminalFormatter) formatSummary(result *diff.Result) error {
	summary := result.Summary

	// Build summary line
	parts := []string{}
	if summary.Added > 0 {
		part := fmt.Sprintf("+%d added", summary.Added)
		if f.useStyles {
			part = f.styles.added.Render(part)
		}
		parts = append(parts, part)
	}
	if summary.Removed > 0 {
		part := fmt.Sprintf("-%d removed", summary.Removed)
		if f.useStyles {
			part = f.styles.removed.Render(part)
		}
		parts = append(parts, part)
	}
	if summary.Modified > 0 {
		part := fmt.Sprintf("~%d modified", summary.Modified)
		if f.useStyles {
			part = f.styles.modified.Render(part)
		}
		parts = append(parts, part)
	}

	header := "Configuration Diff: " + strings.Join(parts, ", ")
	if f.useStyles {
		header = f.styles.summary.Render(header)
	}

	_, err := fmt.Fprintln(f.writer, header)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(f.writer, "")
	return err
}

// formatSection prints a section with its changes.
func (f *TerminalFormatter) formatSection(section diff.Section, changes []diff.Change) error {
	// Section header
	header := "## " + capitalizeFirst(section.String())
	if f.useStyles {
		header = f.styles.sectionHeader.Render(header)
	}
	if _, err := fmt.Fprintln(f.writer, header); err != nil {
		return err
	}

	// Print each change
	for _, change := range changes {
		if err := f.formatChange(change); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintln(f.writer, "")
	return err
}

// capitalizeFirst capitalizes the first letter of a string.
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// formatChange prints a single change.
func (f *TerminalFormatter) formatChange(change diff.Change) error {
	// Symbol with color
	symbol := change.Type.Symbol()
	if f.useStyles {
		switch change.Type {
		case diff.ChangeAdded:
			symbol = f.styles.added.Render(symbol)
		case diff.ChangeRemoved:
			symbol = f.styles.removed.Render(symbol)
		case diff.ChangeModified:
			symbol = f.styles.modified.Render(symbol)
		}
	}

	// Description
	desc := change.Description
	if f.useStyles {
		desc = f.styles.description.Render(desc)
	}

	// Build the line
	line := fmt.Sprintf("  %s %s", symbol, desc)

	// Add security impact if present
	if change.SecurityImpact != "" {
		securityBadge := fmt.Sprintf("[%s]", strings.ToUpper(change.SecurityImpact))
		if f.useStyles {
			switch change.SecurityImpact {
			case "high":
				securityBadge = f.styles.securityHigh.Render(securityBadge)
			case "medium":
				securityBadge = f.styles.securityMedium.Render(securityBadge)
			case "low":
				securityBadge = f.styles.securityLow.Render(securityBadge)
			}
		}
		line += " " + securityBadge
	}

	if _, err := fmt.Fprintln(f.writer, line); err != nil {
		return err
	}

	// Print path
	path := "    Path: " + change.Path
	if f.useStyles {
		path = f.styles.path.Render(path)
	}
	if _, err := fmt.Fprintln(f.writer, path); err != nil {
		return err
	}

	// Print old/new values if present
	if change.OldValue != "" {
		oldVal := "    Old: " + change.OldValue
		if f.useStyles {
			oldVal = f.styles.value.Render(oldVal)
		}
		if _, err := fmt.Fprintln(f.writer, oldVal); err != nil {
			return err
		}
	}
	if change.NewValue != "" {
		newVal := "    New: " + change.NewValue
		if f.useStyles {
			newVal = f.styles.value.Render(newVal)
		}
		if _, err := fmt.Fprintln(f.writer, newVal); err != nil {
			return err
		}
	}

	return nil
}
