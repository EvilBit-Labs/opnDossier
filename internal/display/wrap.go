package display

import (
	"strings"
	"unicode/utf8"
)

// wrapMarkdownContent wraps markdown text to the given width while preserving
// code blocks (fenced with ```) which are never wrapped. Each non-code line
// that exceeds width is passed to wrapMarkdownLine for word-aware breaking.
func wrapMarkdownContent(content string, width int) string {
	if width <= 0 {
		return content
	}

	lines := strings.Split(content, "\n")
	wrapped := make([]string, 0, len(lines))
	inCodeBlock := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inCodeBlock = !inCodeBlock
			wrapped = append(wrapped, line)
			continue
		}
		if inCodeBlock {
			wrapped = append(wrapped, line)
			continue
		}
		if utf8.RuneCountInString(line) <= width {
			wrapped = append(wrapped, line)
			continue
		}

		wrapped = append(wrapped, wrapMarkdownLine(line, width)...)
	}

	return strings.Join(wrapped, "\n")
}

// wrapMarkdownLine breaks a single line of markdown text at word boundaries to
// fit within width (measured in runes). Leading whitespace (indentation) is
// preserved on continuation lines. Words longer than the remaining space are
// split at the rune boundary with a trailing backslash.
func wrapMarkdownLine(line string, width int) []string {
	if width <= 0 || utf8.RuneCountInString(line) <= width {
		return []string{line}
	}

	prefixLen := 0
	for i, r := range line {
		if r != ' ' && r != '\t' {
			prefixLen = i
			break
		}
		if i == len(line)-1 {
			return []string{line}
		}
	}
	prefix := line[:prefixLen]
	text := strings.TrimSpace(line[prefixLen:])
	if text == "" {
		return []string{line}
	}

	words := strings.Fields(text)
	lines := make([]string, 0, len(words))
	current := prefix
	currentLen := prefixLen

	for _, word := range words {
		for word != "" {
			needsSpace := currentLen > prefixLen
			remaining := width - currentLen
			if needsSpace {
				remaining--
			}
			if remaining <= 0 {
				lines = append(lines, current+`\`)
				current = prefix
				currentLen = prefixLen
				continue
			}

			runes := []rune(word)
			if len(runes) > remaining {
				part := string(runes[:remaining])
				if needsSpace {
					current += " " + part
				} else {
					current += part
				}
				lines = append(lines, current+`\`)
				current = prefix
				currentLen = prefixLen
				word = string(runes[remaining:])
				continue
			}

			if needsSpace {
				current += " " + word
			} else {
				current += word
			}
			currentLen = utf8.RuneCountInString(current)
			word = ""
		}
	}

	if strings.TrimSpace(current) != "" {
		lines = append(lines, current)
	}

	return lines
}

// wrapRenderedOutput wraps already-rendered terminal output (which may contain
// ANSI escape sequences) to the given visible width. Each line is processed
// independently by wrapRenderedLine.
func wrapRenderedOutput(output string, width int) string {
	if width <= 0 {
		return output
	}

	lines := strings.Split(output, "\n")
	wrapped := make([]string, 0, len(lines))

	for _, line := range lines {
		wrapped = append(wrapped, wrapRenderedLine(line, width)...)
	}

	return strings.Join(wrapped, "\n")
}

// wrapRenderedLine splits a single rendered line into segments of at most width
// visible characters. ANSI CSI escape sequences (e.g. color codes) are passed
// through without counting toward visible width. Multi-byte UTF-8 characters
// are decoded as whole runes so they are never split mid-sequence.
func wrapRenderedLine(line string, width int) []string {
	if width <= 0 {
		return []string{line}
	}

	visible := 0
	var segments []string
	var builder strings.Builder

	for i := 0; i < len(line); {
		if line[i] == '\x1b' && i+1 < len(line) && line[i+1] == '[' {
			const ansiCSIStartOffset = 2
			end := i + ansiCSIStartOffset
			for end < len(line) {
				b := line[end]
				if (b >= '0' && b <= '9') || b == ';' {
					end++
					continue
				}
				end++
				break
			}
			builder.WriteString(line[i:end])
			i = end
			continue
		}

		r, size := utf8.DecodeRuneInString(line[i:])
		builder.WriteRune(r)
		visible++
		if visible >= width {
			segments = append(segments, builder.String())
			builder.Reset()
			visible = 0
		}
		i += size
	}

	if builder.Len() > 0 || len(segments) == 0 {
		segments = append(segments, builder.String())
	}

	return segments
}
