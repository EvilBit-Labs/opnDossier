// Package converter provides functionality to convert OPNsense configurations to markdown.
package converter

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/unclesp1d3r/opnFocus/internal/model"

	"github.com/charmbracelet/glamour"
)

// Converter is the interface for converting OPNsense configurations to markdown.
type Converter interface {
	ToMarkdown(ctx context.Context, opnsense *model.Opnsense) (string, error)
}

// MarkdownConverter is a markdown converter for OPNsense configurations.
type MarkdownConverter struct{}

// NewMarkdownConverter returns a new instance of MarkdownConverter for converting OPNsense configurations to markdown format.
func NewMarkdownConverter() *MarkdownConverter {
	return &MarkdownConverter{}
}

// ErrNilOpnsense is returned when the input Opnsense struct is nil.
var ErrNilOpnsense = errors.New("input Opnsense struct is nil")

// ToMarkdown converts an OPNsense configuration to markdown.
func (c *MarkdownConverter) ToMarkdown(_ context.Context, opnsense *model.Opnsense) (string, error) {
	if opnsense == nil {
		return "", ErrNilOpnsense
	}

	var b bytes.Buffer

	b.WriteString("# OPNsense Configuration\n\n")
	b.WriteString("## System\n\n")
	b.WriteString(fmt.Sprintf("**Hostname:** %s\n", opnsense.System.Hostname))
	b.WriteString(fmt.Sprintf("**Domain:** %s\n", opnsense.System.Domain))

	r, err := glamour.Render(b.String(), "dark")
	if err != nil {
		return "", fmt.Errorf("failed to render markdown: %w", err)
	}

	return r, nil
}
