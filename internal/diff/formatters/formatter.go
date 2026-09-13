package formatters

import (
	"fmt"
	"io"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
)

// Formatter defines the interface for diff result output formatters.
type Formatter interface {
	Format(result *diff.Result) error
}

// Format name constants.
const (
	FormatTerminal = "terminal"
	FormatMarkdown = "markdown"
	FormatJSON     = "json"
	FormatHTML     = "html"
)

// Display mode constants.
const (
	ModeUnified    = "unified"
	ModeSideBySide = "side-by-side"
)

// NewWithMode creates a Formatter for the given format, display mode, and writer.
func NewWithMode(format, mode string, w io.Writer) (Formatter, error) {
	isSideBySide := strings.EqualFold(mode, ModeSideBySide)

	switch strings.ToLower(format) {
	case FormatTerminal, "":
		if isSideBySide {
			return NewSideBySideFormatter(w), nil
		}
		return NewTerminalFormatter(w), nil
	case FormatMarkdown:
		return NewMarkdownFormatter(w), nil
	case FormatJSON:
		return NewJSONFormatter(w), nil
	case FormatHTML:
		return NewHTMLFormatter(w), nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}
