// Package converter provides functionality to convert OPNsense configurations to markdown.
package converter

import (
	"bytes"
	"fmt"
	"opnFocus/internal/model"

	"github.com/charmbracelet/glamour"
)

// Converter is the interface for converting OPNsense configurations to markdown.
type Converter interface {
	ToMarkdown(opnsense *model.Opnsense) (string, error)
}

// MarkdownConverter is a markdown converter for OPNsense configurations.
type MarkdownConverter struct{}

// NewMarkdownConverter returns a new instance of MarkdownConverter for converting OPNsense configurations to markdown format.
func NewMarkdownConverter() *MarkdownConverter {
	return &MarkdownConverter{}
}

// ToMarkdown converts an OPNsense configuration to markdown.
func (c *MarkdownConverter) ToMarkdown(opnsense *model.Opnsense) (string, error) {
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
