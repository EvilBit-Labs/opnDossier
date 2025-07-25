package converter

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/unclesp1d3r/opnFocus/internal/model"

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
		{
			name:     "nil input",
			input:    nil,
			expected: "",
			wantErr:  true,
		},
		{
			name:     "empty struct",
			input:    &model.Opnsense{},
			expected: "OPNsense Configuration",
			wantErr:  false,
		},
		{
			name: "missing system fields",
			input: &model.Opnsense{
				System: model.System{},
			},
			expected: "OPNsense Configuration",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewMarkdownConverter()
			md, err := c.ToMarkdown(context.Background(), tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, md)
			} else {
				assert.NoError(t, err)

				actual := strings.TrimSpace(stripANSI(md))
				assert.Contains(t, actual, "OPNsense Configuration")
				assert.Contains(t, actual, "## System")

				if tt.input != nil && tt.input.System.Hostname != "" && tt.input.System.Domain != "" {
					assert.Contains(t, actual, "Hostname: "+tt.input.System.Hostname+" Domain: "+tt.input.System.Domain)
				}
			}
		})
	}
}
