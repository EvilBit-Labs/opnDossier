// Package formatters provides output formatting for diff results.
package formatters

import (
	"encoding/json"
	"io"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
)

// JSONFormatter formats diff results as JSON.
type JSONFormatter struct {
	writer io.Writer
	pretty bool
}

// NewJSONFormatter creates a new JSON formatter.
func NewJSONFormatter(writer io.Writer) *JSONFormatter {
	return &JSONFormatter{
		writer: writer,
		pretty: true,
	}
}

// NewJSONFormatterCompact creates a new JSON formatter with compact output.
func NewJSONFormatterCompact(writer io.Writer) *JSONFormatter {
	return &JSONFormatter{
		writer: writer,
		pretty: false,
	}
}

// Format formats the diff result as JSON.
func (f *JSONFormatter) Format(result *diff.Result) error {
	encoder := json.NewEncoder(f.writer)
	if f.pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(result)
}

// SetPretty sets whether to output formatted JSON.
func (f *JSONFormatter) SetPretty(pretty bool) {
	f.pretty = pretty
}
