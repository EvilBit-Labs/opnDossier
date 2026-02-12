package formatters

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
	"golang.org/x/term"
)

// minTerminalWidth is the minimum terminal width required for side-by-side display.
const minTerminalWidth = 80

// defaultTerminalWidth is used when terminal width cannot be detected.
const defaultTerminalWidth = 120

// sideBySideGutter is the width of the center gutter between columns.
const sideBySideGutter = 3

// sideBySideColumns is the number of columns in side-by-side layout.
const sideBySideColumns = 2

// valueColumnPadding is the left padding for value lines in side-by-side layout.
const valueColumnPadding = 4

// valueTruncationMargin accounts for indentation in value display.
const valueTruncationMargin = 6

// ellipsisLen is the length of the truncation indicator "...".
const ellipsisLen = 3

// SideBySideFormatter formats diff results in a two-column terminal layout.
type SideBySideFormatter struct {
	writer    io.Writer
	useStyles bool
	styles    terminalStyles
	width     int
}

// NewSideBySideFormatter creates a new side-by-side terminal formatter.
func NewSideBySideFormatter(writer io.Writer) *SideBySideFormatter {
	useStyles := shouldUseStyles()
	width := detectTerminalWidth()
	return &SideBySideFormatter{
		writer:    writer,
		useStyles: useStyles,
		styles:    createStyles(useStyles),
		width:     width,
	}
}

// detectTerminalWidth returns the terminal width, or a default if detection fails.
// Note: always queries os.Stdout regardless of the formatter's io.Writer, since
// side-by-side output is only meaningful for interactive terminal sessions.
func detectTerminalWidth() int {
	fd := int(os.Stdout.Fd())
	width, _, err := term.GetSize(fd)
	if err != nil || width <= 0 {
		return defaultTerminalWidth
	}
	return width
}

// Format formats the diff result in a side-by-side layout.
// Falls back to unified format if the terminal is too narrow.
func (f *SideBySideFormatter) Format(result *diff.Result) error {
	if f.width < minTerminalWidth {
		// Fall back to unified terminal format
		unified := &TerminalFormatter{
			writer:    f.writer,
			useStyles: f.useStyles,
			styles:    f.styles,
		}
		return unified.Format(result)
	}

	if !result.HasChanges() {
		return f.formatNoChanges()
	}

	if err := f.formatHeader(result); err != nil {
		return err
	}

	bySection := result.ChangesBySection()
	sections := make([]diff.Section, 0, len(bySection))
	for s := range bySection {
		sections = append(sections, s)
	}
	sort.Slice(sections, func(i, j int) bool {
		return sections[i].String() < sections[j].String()
	})

	for _, section := range sections {
		if err := f.formatSection(section, bySection[section]); err != nil {
			return err
		}
	}

	return nil
}

// formatNoChanges prints a message when there are no changes.
func (f *SideBySideFormatter) formatNoChanges() error {
	msg := "No changes detected between configurations."
	if f.useStyles {
		msg = f.styles.noChanges.Render(msg)
	}
	_, err := fmt.Fprintln(f.writer, msg)
	return err
}

// formatHeader prints the comparison header with summary.
func (f *SideBySideFormatter) formatHeader(result *diff.Result) error {
	colWidth := (f.width - sideBySideGutter) / sideBySideColumns

	oldLabel := "OLD"
	newLabel := "NEW"
	if f.useStyles {
		oldLabel = f.styles.removed.Render(oldLabel)
		newLabel = f.styles.added.Render(newLabel)
	}

	// Print column headers
	header := fmt.Sprintf("%-*s │ %s", colWidth, oldLabel, newLabel)
	if _, err := fmt.Fprintln(f.writer, header); err != nil {
		return err
	}

	// Print separator
	sep := strings.Repeat("─", colWidth) + "─┼─" + strings.Repeat("─", colWidth)
	if _, err := fmt.Fprintln(f.writer, sep); err != nil {
		return err
	}

	// Print summary
	s := result.Summary
	summary := fmt.Sprintf("+%d added, -%d removed, ~%d modified", s.Added, s.Removed, s.Modified)
	if s.Reordered > 0 {
		summary += fmt.Sprintf(", ↕%d reordered", s.Reordered)
	}
	summary += fmt.Sprintf(" (%d total)", s.Total)
	if f.useStyles {
		summary = f.styles.summary.Render(summary)
	}
	if _, err := fmt.Fprintln(f.writer, summary); err != nil {
		return err
	}
	_, err := fmt.Fprintln(f.writer)
	return err
}

// formatSection prints a section with side-by-side change details.
func (f *SideBySideFormatter) formatSection(section diff.Section, changes []diff.Change) error {
	header := "## " + capitalizeFirst(section.String())
	if f.useStyles {
		header = f.styles.sectionHeader.Render(header)
	}
	if _, err := fmt.Fprintln(f.writer, header); err != nil {
		return err
	}

	colWidth := (f.width - sideBySideGutter) / sideBySideColumns

	for _, change := range changes {
		if err := f.formatChangeSideBySide(change, colWidth); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintln(f.writer)
	return err
}

// formatChangeSideBySide prints a single change in side-by-side format.
func (f *SideBySideFormatter) formatChangeSideBySide(change diff.Change, colWidth int) error {
	// Build the description line with symbol
	symbol := change.Type.Symbol()
	desc := change.Description

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

	// Security badge
	secBadge := ""
	if change.SecurityImpact != "" {
		secBadge = fmt.Sprintf(" [%s]", strings.ToUpper(change.SecurityImpact))
		if f.useStyles {
			switch change.SecurityImpact {
			case "high":
				secBadge = " " + f.styles.securityHigh.Render(
					fmt.Sprintf("[%s]", strings.ToUpper(change.SecurityImpact)),
				)
			case "medium":
				secBadge = " " + f.styles.securityMedium.Render(
					fmt.Sprintf("[%s]", strings.ToUpper(change.SecurityImpact)),
				)
			case "low":
				secBadge = " " + f.styles.securityLow.Render(
					fmt.Sprintf("[%s]", strings.ToUpper(change.SecurityImpact)),
				)
			}
		}
	}

	// Print description line spanning full width
	line := fmt.Sprintf("  %s %s%s", symbol, desc, secBadge)
	if _, err := fmt.Fprintln(f.writer, line); err != nil {
		return err
	}

	// Print old/new values side by side
	oldVal := truncate(change.OldValue, colWidth-valueTruncationMargin)
	newVal := truncate(change.NewValue, colWidth-valueTruncationMargin)

	if oldVal != "" || newVal != "" {
		if f.useStyles {
			oldVal = f.styles.value.Render(oldVal)
			newVal = f.styles.value.Render(newVal)
		}
		valLine := fmt.Sprintf("    %-*s │ %s", colWidth-valueColumnPadding, oldVal, newVal)
		if _, err := fmt.Fprintln(f.writer, valLine); err != nil {
			return err
		}
	}

	return nil
}

// truncate truncates a string to maxLen, adding "..." if truncated.
func truncate(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	if maxLen <= ellipsisLen {
		return s[:maxLen]
	}
	return s[:maxLen-ellipsisLen] + "..."
}
