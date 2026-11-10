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

	// reHTMLListTag matches the list tags the nested-list renderer walks: the
	// opening and closing <ul>, <ol> (with any attributes) and <li> tags.
	reHTMLListTag = regexp.MustCompile(`(?i)<(/?)(ul|ol|li)\b[^>]*>`)
)

// placeholderFmt is a unique marker format that survives html2text processing.
// Uses a prefix unlikely to appear in normal content. The index is terminated
// so that no placeholder is a prefix of another: without the terminator the
// marker for index 1 matched inside the marker for index 10, and a document
// with eleven placeholders restored the wrong one.
const placeholderFmt = "OPNDOSSIER_PH_%d_END"

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
	// Nested lists are restored after the whitespace trim, which would strip
	// their indentation, so their placeholders start at firstList.
	firstList := counter
	htmlContent = extractNestedListsWithPlaceholders(htmlContent, &replacements, &counter)

	// Stage 3: Convert remaining HTML to text
	text := html2text.HTML2TextWithOptions(
		htmlContent,
		html2text.WithUnixLineBreaks(),
		html2text.WithListSupportPrefix("- "),
	)

	// Stage 4: Replace table and alert placeholders with formatted text
	for i, replacement := range replacements[:firstList] {
		text = strings.Replace(text, fmt.Sprintf(placeholderFmt, i), replacement, 1)
	}

	// Stage 5: Post-process text output
	text = trimLineWhitespace(text)
	text = reExcessiveNewlines.ReplaceAllString(text, "\n\n")

	// Stage 6: Restore nested lists, whose indentation the trim would have
	// stripped, then any table or alert placeholder one of them carried.
	for i := firstList; i < len(replacements); i++ {
		text = strings.Replace(text, fmt.Sprintf(placeholderFmt, i), replacements[i], 1)
	}
	for i, replacement := range replacements[:firstList] {
		text = replaceIndented(text, fmt.Sprintf(placeholderFmt, i), replacement)
	}

	return strings.TrimSpace(text) + "\n", nil
}

// replaceIndented replaces the first occurrence of placeholder in text with
// replacement, indenting every line of the replacement after the first by
// the whitespace that precedes the placeholder on its line, so a table
// restored inside a nested list item sits at the item's indentation.
func replaceIndented(text, placeholder, replacement string) string {
	at := strings.Index(text, placeholder)
	if at < 0 {
		return text
	}
	lineStart := strings.LastIndex(text[:at], "\n") + 1
	indent := text[lineStart:at]
	if strings.TrimSpace(indent) == "" && indent != "" {
		replacement = strings.ReplaceAll(replacement, "\n", "\n"+indent)
	}
	return text[:at] + replacement + text[at+len(placeholder):]
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
// the first. The HTML between two list tags is one item's content: the text
// that opens an item, or what follows a nested list inside it, such as a
// continuation paragraph, which is written on its own line at the item's
// indentation. Each piece goes through html2text so emphasis, links and
// entities read as they do elsewhere in the document.
func renderListBlock(block string) string {
	tags := reHTMLListTag.FindAllStringSubmatchIndex(block, -1)

	var lines []string
	depth := 0
	for i, tag := range tags {
		closing := block[tag[2]:tag[3]] == "/"
		isItem := strings.EqualFold(block[tag[4]:tag[5]], "li")
		switch {
		case isItem:
		case closing:
			depth--
		default:
			depth++
		}

		end := len(block)
		if i+1 < len(tags) {
			end = tags[i+1][0]
		}
		content := html2text.HTML2TextWithOptions(block[tag[1]:end], html2text.WithUnixLineBreaks())
		text := strings.Join(strings.Fields(content), " ")
		indent := strings.Repeat("  ", max(depth-1, 0))
		switch {
		case isItem && !closing:
			lines = append(lines, indent+"- "+text)
		case text != "":
			lines = append(lines, indent+"  "+text)
		}
	}
	return strings.Join(lines, "\n")
}

// trimLineWhitespace strips leading and trailing whitespace from each line.
// html2text produces artifact whitespace: leading spaces after headings/HRs,
// and trailing spaces on list items. TrimSpace is safe here because nothing
// it sees carries intentional indentation: tables use tab-separated
// placeholders, and a nested list, whose indentation is intentional, is
// restored from its placeholder only after this runs.
func trimLineWhitespace(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.Join(lines, "\n")
}
