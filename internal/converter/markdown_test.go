package converter

import (
	"opnFocus/internal/model"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var ansiStripper = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiStripper.ReplaceAllString(s, "")
}

func TestMarkdownConverter_ToMarkdown(t *testing.T) {
	tests := []struct {
		name     string
		input    *model.Opnsense
		expected string
		wantErr  bool
	}{
		{
			name: "basic conversion",
			input: &model.Opnsense{
				Version: "1.2.3",
				System: model.System{
					Hostname: "test-host",
					Domain:   "test.local",
				},
			},
			expected: `OPNsense Configuration

  ## System

  Hostname: test-host Domain: test.local`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewMarkdownConverter()
			md, err := c.ToMarkdown(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, md)
			} else {
				assert.NoError(t, err)
				// Clean up whitespace and ANSI escape codes for comparison
				actual := strings.TrimSpace(stripANSI(md))

				// Check that the markdown contains key content rather than exact match
				assert.Contains(t, actual, "OPNsense Configuration")
				assert.Contains(t, actual, "## System")
				assert.Contains(t, actual, "Hostname: test-host Domain: test.local")
			}
		})
	}
}
