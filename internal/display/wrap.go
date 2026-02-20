package display

import (
	"strings"
	"unicode/utf8"
)

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
		if len(line) <= width {
			wrapped = append(wrapped, line)
			continue
		}

		wrapped = append(wrapped, wrapMarkdownLine(line, width)...)
	}

	return strings.Join(wrapped, "\n")
}

func wrapMarkdownLine(line string, width int) []string {
	if width <= 0 || len(line) <= width {
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
			currentLen = len(current)
			word = ""
		}
	}

	if strings.TrimSpace(current) != "" {
		lines = append(lines, current)
	}

	return lines
}

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
