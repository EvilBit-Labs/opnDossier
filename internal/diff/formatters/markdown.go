// Package formatters provides output formatting for diff results.
package formatters

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
)

// MarkdownFormatter formats diff results as markdown.
type MarkdownFormatter struct {
	writer io.Writer
}

// NewMarkdownFormatter creates a new markdown formatter.
func NewMarkdownFormatter(writer io.Writer) *MarkdownFormatter {
	return &MarkdownFormatter{
		writer: writer,
	}
}

// Format formats the diff result as markdown.
func (f *MarkdownFormatter) Format(result *diff.Result) error {
	// Header
	if _, err := fmt.Fprintln(f.writer, "# Configuration Diff"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f.writer); err != nil {
		return err
	}

	// Metadata
	if err := f.formatMetadata(result); err != nil {
		return err
	}

	// Summary
	if err := f.formatSummary(result); err != nil {
		return err
	}

	if !result.HasChanges() {
		_, err := fmt.Fprintln(f.writer, "*No changes detected.*")
		return err
	}

	// Changes by section
	return f.formatChanges(result)
}

// formatMetadata outputs the comparison metadata.
func (f *MarkdownFormatter) formatMetadata(result *diff.Result) error {
	meta := result.Metadata

	if meta.OldFile != "" {
		if _, err := fmt.Fprintf(f.writer, "**Old File:** `%s`\n", meta.OldFile); err != nil {
			return err
		}
	}
	if meta.NewFile != "" {
		if _, err := fmt.Fprintf(f.writer, "**New File:** `%s`\n", meta.NewFile); err != nil {
			return err
		}
	}
	if !meta.ComparedAt.IsZero() {
		if _, err := fmt.Fprintf(
			f.writer,
			"**Compared At:** %s\n",
			meta.ComparedAt.Format("2006-01-02 15:04:05"),
		); err != nil {
			return err
		}
	}
	if meta.ToolVersion != "" {
		if _, err := fmt.Fprintf(f.writer, "**Tool Version:** %s\n", meta.ToolVersion); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(f.writer)
	return err
}

// formatSummary outputs the change summary.
func (f *MarkdownFormatter) formatSummary(result *diff.Result) error {
	if _, err := fmt.Fprintln(f.writer, "## Summary"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f.writer); err != nil {
		return err
	}

	summary := result.Summary

	// Summary table
	if _, err := fmt.Fprintln(f.writer, "| Type | Count |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f.writer, "|------|-------|"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f.writer, "| Added | %d |\n", summary.Added); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f.writer, "| Removed | %d |\n", summary.Removed); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f.writer, "| Modified | %d |\n", summary.Modified); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f.writer, "| **Total** | **%d** |\n", summary.Total); err != nil {
		return err
	}
	_, err := fmt.Fprintln(f.writer)
	return err
}

// formatChanges outputs all changes grouped by section.
func (f *MarkdownFormatter) formatChanges(result *diff.Result) error {
	bySection := result.ChangesBySection()

	// Get sorted section names for deterministic output
	sections := make([]diff.Section, 0, len(bySection))
	for section := range bySection {
		sections = append(sections, section)
	}
	sort.Slice(sections, func(i, j int) bool {
		return sections[i].String() < sections[j].String()
	})

	for _, section := range sections {
		changes := bySection[section]
		if err := f.formatSection(section, changes); err != nil {
			return err
		}
	}

	return nil
}

// formatSection outputs a single section with its changes.
func (f *MarkdownFormatter) formatSection(section diff.Section, changes []diff.Change) error {
	// Section header
	if _, err := fmt.Fprintf(f.writer, "## %s\n\n", capitalizeFirst(section.String())); err != nil {
		return err
	}

	// Changes table
	if _, err := fmt.Fprintln(f.writer, "| Change | Description | Security |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f.writer, "|--------|-------------|----------|"); err != nil {
		return err
	}

	for _, change := range changes {
		symbol := changeSymbolMarkdown(change.Type)
		security := ""
		if change.SecurityImpact != "" {
			security = securityBadge(change.SecurityImpact)
		}

		if _, err := fmt.Fprintf(f.writer, "| %s | %s | %s |\n",
			symbol, escapeMarkdown(change.Description), security); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(f.writer); err != nil {
		return err
	}

	// Detailed changes
	if _, err := fmt.Fprintln(f.writer, "<details>"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f.writer, "<summary>Show details</summary>"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f.writer); err != nil {
		return err
	}

	for _, change := range changes {
		if err := f.formatChangeDetails(change); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(f.writer, "</details>"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(f.writer)
	return err
}

// formatChangeDetails outputs detailed information for a single change.
func (f *MarkdownFormatter) formatChangeDetails(change diff.Change) error {
	symbol := changeSymbolMarkdown(change.Type)
	if _, err := fmt.Fprintf(f.writer, "### %s %s\n\n", symbol, change.Description); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(f.writer, "- **Path:** `%s`\n", change.Path); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f.writer, "- **Type:** %s\n", change.Type.String()); err != nil {
		return err
	}

	if change.SecurityImpact != "" {
		if _, err := fmt.Fprintf(
			f.writer,
			"- **Security Impact:** %s\n",
			securityBadge(change.SecurityImpact),
		); err != nil {
			return err
		}
	}

	if change.OldValue != "" {
		if _, err := fmt.Fprintf(f.writer, "- **Old Value:** `%s`\n", change.OldValue); err != nil {
			return err
		}
	}
	if change.NewValue != "" {
		if _, err := fmt.Fprintf(f.writer, "- **New Value:** `%s`\n", change.NewValue); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintln(f.writer)
	return err
}

// changeSymbolMarkdown returns a markdown-formatted symbol for the change type.
func changeSymbolMarkdown(changeType diff.ChangeType) string {
	switch changeType {
	case diff.ChangeAdded:
		return "**+**"
	case diff.ChangeRemoved:
		return "**-**"
	case diff.ChangeModified:
		return "**~**"
	default:
		return "**?**"
	}
}

// securityBadge returns a formatted security impact badge.
func securityBadge(impact string) string {
	switch strings.ToLower(impact) {
	case string(diff.SecurityImpactHigh):
		return "🔴 HIGH"
	case string(diff.SecurityImpactMedium):
		return "🟡 MEDIUM"
	case string(diff.SecurityImpactLow):
		return "🟢 LOW"
	default:
		return impact
	}
}

// escapeMarkdown escapes special markdown characters in a string.
func escapeMarkdown(s string) string {
	// Escape pipe characters for table cells
	return strings.ReplaceAll(s, "|", "\\|")
}
