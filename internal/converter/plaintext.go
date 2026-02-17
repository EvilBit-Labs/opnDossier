package converter

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/k3a/html2text"
)

// Precompiled regex patterns for HTML-to-plaintext pre/post-processing.
// These are compiled once at init and are safe for concurrent use.
var (
	// reHTMLTable matches a complete <table>...</table> element.
	reHTMLTable = regexp.MustCompile(`(?s)<table>.*?</table>`)

	// reHTMLTableRow matches a <tr>...</tr> element.
	reHTMLTableRow = regexp.MustCompile(`(?s)<tr>(.*?)</tr>`)

	// reHTMLTableCell matches <th> or <td> elements and captures inner content.
	reHTMLTableCell = regexp.MustCompile(`(?s)<t[hd][^>]*>(.*?)</t[hd]>`)

	// reAlertBlockquoteText matches goldmark blockquote output containing alert markers
	// for plaintext conversion. Converts to "TYPE:\ntext" format.
	reAlertBlockquoteText = regexp.MustCompile(
		`(?s)<blockquote>\s*<p>\[!(NOTE|WARNING|TIP|CAUTION|IMPORTANT)\]` +
			`(?:<br\s*/?>)?\s*\n?(.*?)</p>\s*</blockquote>`,
	)

	// reHTMLLink matches anchor tags and captures href and inner text.
	reHTMLLink = regexp.MustCompile(`(?s)<a\s+[^>]*href="([^"]*)"[^>]*>(.*?)</a>`)

	// reHTMLTag matches any HTML tag for stripping from extracted content.
	reHTMLTag = regexp.MustCompile(`<[^>]+>`)

	// reExcessiveNewlines collapses 3+ consecutive newlines to 2.
	reExcessiveNewlines = regexp.MustCompile(`\n{3,}`)
)

// placeholderFmt is a unique marker format that survives html2text processing.
// Uses a prefix unlikely to appear in normal content.
const placeholderFmt = "OPNDOSSIER_PH_%d"

// stripMarkdownFormatting converts markdown to plain text using a
// goldmark -> HTML -> html2text pipeline. The goldmark renderer (shared
// with HTML output) handles all markdown parsing, while html2text
// provides proper HTML-to-text conversion using Go's net/html parser.
//
// Tables and alerts are extracted from the HTML before html2text processing
// (using placeholders) because html2text doesn't handle table layout or
// preserve the tab-separated formatting we need.
func stripMarkdownFormatting(markdown string) string {
	// Stage 1: Render markdown to HTML via goldmark (shared renderer from html.go)
	var buf strings.Builder
	if err := goldmarkRenderer.Convert([]byte(markdown), &buf); err != nil {
		return markdown
	}
	htmlContent := buf.String()

	// Stage 2: Extract elements needing custom formatting, replace with placeholders.
	// Placeholders survive html2text since they're plain ASCII text.
	var replacements []string
	counter := 0

	htmlContent = extractTablesWithPlaceholders(htmlContent, &replacements, &counter)
	htmlContent = convertLinksToPlainText(htmlContent)
	htmlContent = extractAlertsWithPlaceholders(htmlContent, &replacements, &counter)

	// Stage 3: Convert remaining HTML to text
	text := html2text.HTML2TextWithOptions(
		htmlContent,
		html2text.WithUnixLineBreaks(),
		html2text.WithListSupportPrefix("- "),
	)

	// Stage 4: Replace placeholders with formatted text
	for i, replacement := range replacements {
		text = strings.Replace(text, fmt.Sprintf(placeholderFmt, i), replacement, 1)
	}

	// Stage 5: Post-process text output
	text = trimLineWhitespace(text)
	text = reExcessiveNewlines.ReplaceAllString(text, "\n\n")

	return strings.TrimSpace(text) + "\n"
}

// extractTablesWithPlaceholders replaces HTML tables with placeholders and stores
// tab-separated text representations in the replacements slice.
func extractTablesWithPlaceholders(htmlContent string, replacements *[]string, counter *int) string {
	return reHTMLTable.ReplaceAllStringFunc(htmlContent, func(tableHTML string) string {
		rows := reHTMLTableRow.FindAllStringSubmatch(tableHTML, -1)
		var lines []string
		for _, row := range rows {
			cells := reHTMLTableCell.FindAllStringSubmatch(row[1], -1)
			var values []string
			for _, cell := range cells {
				cellText := reHTMLTag.ReplaceAllString(cell[1], "")
				values = append(values, strings.TrimSpace(cellText))
			}
			lines = append(lines, strings.Join(values, "\t"))
		}

		placeholder := fmt.Sprintf("<p>"+placeholderFmt+"</p>", *counter)
		*replacements = append(*replacements, strings.Join(lines, "\n"))
		*counter++
		return placeholder
	})
}

// extractAlertsWithPlaceholders replaces alert blockquotes with placeholders and
// stores "TYPE:\ntext" representations in the replacements slice.
func extractAlertsWithPlaceholders(htmlContent string, replacements *[]string, counter *int) string {
	return reAlertBlockquoteText.ReplaceAllStringFunc(htmlContent, func(match string) string {
		submatch := reAlertBlockquoteText.FindStringSubmatch(match)
		if len(submatch) < alertSubmatchLen {
			return match
		}
		alertType := submatch[1]
		body := reHTMLTag.ReplaceAllString(submatch[2], "")
		body = strings.TrimSpace(body)

		placeholder := fmt.Sprintf("<p>"+placeholderFmt+"</p>", *counter)
		*replacements = append(*replacements, alertType+":\n"+body)
		*counter++
		return placeholder
	})
}

// convertLinksToPlainText replaces <a href="url">text</a> with "text (url)".
func convertLinksToPlainText(htmlContent string) string {
	return reHTMLLink.ReplaceAllString(htmlContent, "$2 ($1)")
}

// trimLineWhitespace removes leading and trailing whitespace from each line
// while preserving intentional indentation in tab-separated table content.
// This cleans up artifacts from html2text (leading spaces after headings/HRs,
// trailing spaces on list items).
func trimLineWhitespace(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.Join(lines, "\n")
}
