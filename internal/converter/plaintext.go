package converter

import (
	"regexp"
	"strings"
)

// Precompiled regex patterns for markdown stripping.
var (
	reHeading     = regexp.MustCompile(`(?m)^#{1,6}\s+`)
	reLink        = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	reInlineCode  = regexp.MustCompile("`([^`]+)`")
	reCodeFence   = regexp.MustCompile("(?m)^```[a-z]*\\s*$")
	reHRule       = regexp.MustCompile(`(?m)^-{3,}\s*$`)
	reHTMLTag     = regexp.MustCompile(`<[^>]+>`)
	reTableSep    = regexp.MustCompile(`(?m)^\|[\s:|-]+\|\s*$`)
	reAlertMarker = regexp.MustCompile(`(?m)^>\s*\[!(NOTE|WARNING|TIP|CAUTION|IMPORTANT)\]\s*$`)
	reItalicStar  = regexp.MustCompile(`\*([^*\n]+)\*`)
	reItalicUndsc = regexp.MustCompile(`_([^_\n]+)_`)
	reBlockquote  = regexp.MustCompile(`(?m)^>\s?`)
	reEmptyLines  = regexp.MustCompile(`\n{3,}`)
)

// stripMarkdownFormatting removes markdown formatting from the input text,
// producing clean plain text output while preserving content structure.
func stripMarkdownFormatting(markdown string) string {
	text := markdown

	// Convert links [text](url) to "text (url)"
	text = reLink.ReplaceAllString(text, "$1 ($2)")

	// Remove heading markers
	text = reHeading.ReplaceAllString(text, "")

	// Remove bold markers first (** and __), then italic (* and _)
	text = strings.ReplaceAll(text, "**", "")
	text = strings.ReplaceAll(text, "__", "")
	text = reItalicStar.ReplaceAllString(text, "$1")
	text = reItalicUndsc.ReplaceAllString(text, "$1")

	// Remove code fences
	text = reCodeFence.ReplaceAllString(text, "")

	// Remove inline code backticks (preserve content)
	text = reInlineCode.ReplaceAllString(text, "$1")

	// Remove horizontal rules
	text = reHRule.ReplaceAllString(text, "")

	// Convert alert markers to plain labels
	text = reAlertMarker.ReplaceAllStringFunc(text, func(match string) string {
		submatch := reAlertMarker.FindStringSubmatch(match)
		if len(submatch) > 1 {
			return submatch[1] + ":"
		}
		return match
	})

	// Remove blockquote markers
	text = reBlockquote.ReplaceAllString(text, "")

	// Convert table rows: strip leading/trailing pipes, replace inner pipes with spacing
	text = convertTableRows(text)

	// Remove HTML tags
	text = reHTMLTag.ReplaceAllString(text, "")

	// Collapse excessive blank lines to at most two
	text = reEmptyLines.ReplaceAllString(text, "\n\n")

	return strings.TrimSpace(text) + "\n"
}

// convertTableRows converts markdown table rows to plain text with tab-separated columns.
func convertTableRows(text string) string {
	// Remove table separator rows (|---|---|)
	text = reTableSep.ReplaceAllString(text, "")

	lines := strings.Split(text, "\n")
	result := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "|") && strings.HasSuffix(trimmed, "|") {
			// Strip outer pipes and convert inner pipes to tab separators
			inner := trimmed[1 : len(trimmed)-1]
			cells := strings.Split(inner, "|")
			cleaned := make([]string, 0, len(cells))
			for _, cell := range cells {
				cleaned = append(cleaned, strings.TrimSpace(cell))
			}
			result = append(result, strings.Join(cleaned, "\t"))
		} else {
			result = append(result, line)
		}
	}

	return strings.Join(result, "\n")
}
