package converter

import (
	"fmt"
	"regexp"
	"slices"
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

	// reHTMLListTag matches the list tags the nested-list renderer walks: the
	// opening and closing <ul>, <ol> (with any attributes) and <li> tags.
	reHTMLListTag = regexp.MustCompile(`(?i)<(/?)(ul|ol|li)\b[^>]*>`)

	// reIndentedListItem matches a line renderListBlock indented: two spaces
	// per nesting level in front of the "- " list prefix.
	reIndentedListItem = regexp.MustCompile(`^(?: {2})+- `)
)

// placeholderFmt is a unique marker format that survives html2text processing.
// Uses a prefix unlikely to appear in normal content.
const placeholderFmt = "OPNDOSSIER_PH_%d"

// StripMarkdownFormatting converts markdown to plain text using a
// goldmark -> HTML -> html2text pipeline. goldmarkRenderer handles all markdown
// parsing, while html2text provides proper HTML-to-text conversion using Go's
// net/html parser.
//
// goldmarkRenderer is dedicated to this pipeline and is not the renderer behind
// RenderMarkdownToHTML; see its declaration in html.go for why it alone keeps
// raw-HTML passthrough enabled.
//
// Tables and alerts are extracted from the HTML before html2text processing
// (using placeholders) because html2text doesn't handle table layout or
// preserve the tab-separated formatting we need.
func StripMarkdownFormatting(markdown string) (string, error) {
	// Stage 1: Render markdown to the intermediate HTML html2text consumes.
	var buf strings.Builder
	if err := goldmarkRenderer.Convert([]byte(markdown), &buf); err != nil {
		return "", fmt.Errorf("failed to convert markdown to plain text: %w", err)
	}
	htmlContent := buf.String()

	// Stage 2: Extract elements needing custom formatting, replace with placeholders.
	// Placeholders survive html2text since they're plain ASCII text.
	var replacements []string
	counter := 0

	htmlContent = extractTablesWithPlaceholders(htmlContent, &replacements, &counter)
	htmlContent = convertLinksToPlainText(htmlContent)
	htmlContent = extractAlertsWithPlaceholders(htmlContent, &replacements, &counter)
	htmlContent = extractNestedListsWithPlaceholders(htmlContent, &replacements, &counter)

	// Stage 3: Convert remaining HTML to text
	text := html2text.HTML2TextWithOptions(
		htmlContent,
		html2text.WithUnixLineBreaks(),
		html2text.WithListSupportPrefix("- "),
	)

	// Stage 4: Replace placeholders with formatted text. Later placeholders
	// are restored first, so one that was extracted from inside an earlier
	// one, such as a table inside a list item, is restored by its turn.
	for i, replacement := range slices.Backward(replacements) {
		text = strings.Replace(text, fmt.Sprintf(placeholderFmt, i), replacement, 1)
	}

	// Stage 5: Post-process text output
	text = trimLineWhitespace(text)
	text = reExcessiveNewlines.ReplaceAllString(text, "\n\n")

	return strings.TrimSpace(text) + "\n", nil
}

// extractTablesWithPlaceholders replaces HTML tables with placeholders and stores
// tab-separated text representations in the replacements slice.
func extractTablesWithPlaceholders(htmlContent string, replacements *[]string, counter *int) string {
	return reHTMLTable.ReplaceAllStringFunc(htmlContent, func(tableHTML string) string {
		rows := reHTMLTableRow.FindAllStringSubmatch(tableHTML, -1)
		lines := make([]string, 0, len(rows))
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

// extractNestedListsWithPlaceholders replaces each top-level list that holds a
// nested list with a placeholder and stores its rendered text in replacements.
// html2text gives every <li> the same prefix whatever its depth, so a nested
// list would come out flat (the audit report's recommendations are one bullet
// per component with the recommendations nested under it). A list with no
// nesting is left to html2text, so its output is unchanged.
func extractNestedListsWithPlaceholders(htmlContent string, replacements *[]string, counter *int) string {
	tags := reHTMLListTag.FindAllStringSubmatchIndex(htmlContent, -1)

	var out strings.Builder
	last, depth, start := 0, 0, 0
	nested := false
	for _, tag := range tags {
		closing := htmlContent[tag[2]:tag[3]] == "/"
		if strings.EqualFold(htmlContent[tag[4]:tag[5]], "li") {
			continue
		}
		if !closing {
			if depth == 0 {
				start, nested = tag[0], false
			} else {
				nested = true
			}
			depth++
			continue
		}
		if depth == 0 {
			continue
		}
		depth--
		if depth > 0 || !nested {
			continue
		}
		out.WriteString(htmlContent[last:start])
		fmt.Fprintf(&out, placeholderFmt, *counter)
		*replacements = append(*replacements, renderListBlock(htmlContent[start:tag[1]]))
		*counter++
		last = tag[1]
	}
	out.WriteString(htmlContent[last:])
	return out.String()
}

// renderListBlock renders one list element, nested lists included, as text:
// one line per item with the "- " prefix, indented two spaces per level below
// the first. An item's own inline content, the HTML between its <li> and the
// next list tag, goes through html2text so emphasis, links and entities read
// as they do elsewhere in the document.
func renderListBlock(block string) string {
	tags := reHTMLListTag.FindAllStringSubmatchIndex(block, -1)

	var lines []string
	depth := 0
	for i, tag := range tags {
		closing := block[tag[2]:tag[3]] == "/"
		if !strings.EqualFold(block[tag[4]:tag[5]], "li") {
			if closing {
				depth--
			} else {
				depth++
			}
			continue
		}
		if closing {
			continue
		}
		end := len(block)
		if i+1 < len(tags) {
			end = tags[i+1][0]
		}
		item := html2text.HTML2TextWithOptions(block[tag[1]:end], html2text.WithUnixLineBreaks())
		indent := strings.Repeat("  ", max(depth-1, 0))
		lines = append(lines, indent+"- "+strings.Join(strings.Fields(item), " "))
	}
	return strings.Join(lines, "\n")
}

// trimLineWhitespace strips trailing whitespace from each line, and leading
// whitespace too unless the line is an indented list item. html2text produces
// artifact whitespace: leading spaces after headings/HRs, and trailing spaces
// on list items. Tables use tab-separated placeholders, restored before this
// runs, and the only intentional indentation is the two spaces per level
// renderListBlock writes in front of a nested item.
func trimLineWhitespace(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if reIndentedListItem.MatchString(line) {
			lines[i] = strings.TrimRight(line, " \t\r")
			continue
		}
		lines[i] = strings.TrimSpace(line)
	}
	return strings.Join(lines, "\n")
}
