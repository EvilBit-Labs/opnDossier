package converter

import (
	"bytes"
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripMarkdownFormatting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "heading removal",
			input:    "# Heading 1\n## Heading 2\n### Heading 3\n",
			expected: "Heading 1\n\nHeading 2\n\nHeading 3\n",
		},
		{
			name:     "bold removal",
			input:    "This is **bold** text and __also bold__ text.\n",
			expected: "This is bold text and also bold text.\n",
		},
		{
			name:     "link conversion",
			input:    "Visit [Google](https://google.com) for search.\n",
			expected: "Visit Google (https://google.com) for search.\n",
		},
		{
			name:     "italic asterisk removal",
			input:    "This is *italic* text.\n",
			expected: "This is italic text.\n",
		},
		{
			name:     "italic underscore removal",
			input:    "This is _italic_ text.\n",
			expected: "This is italic text.\n",
		},
		{
			name:     "bold and italic combined",
			input:    "**bold** and *italic* and _also italic_\n",
			expected: "bold and italic and also italic\n",
		},
		{
			name:     "inline code removal",
			input:    "Use `fmt.Println` to print.\n",
			expected: "Use fmt.Println to print.\n",
		},
		{
			name:     "code fence removal",
			input:    "```go\nfmt.Println(\"hello\")\n```\n",
			expected: "fmt.Println(\"hello\")\n",
		},
		{
			name:     "horizontal rule removal",
			input:    "Above\n---\nBelow\n",
			expected: "Above\n\nBelow\n",
		},
		{
			name:     "html tag removal",
			input:    "<details><summary>Click</summary>Content</details>\n",
			expected: "ClickContent\n",
		},
		{
			name:     "table conversion",
			input:    "| Name | Value |\n|------|-------|\n| foo  | bar   |\n",
			expected: "Name\tValue\nfoo\tbar\n",
		},
		{
			name:     "alert marker conversion",
			input:    "> [!WARNING]\n> This is a warning\n",
			expected: "WARNING:\nThis is a warning\n",
		},
		{
			name:     "blockquote removal",
			input:    "> This is a quote\n> Second line\n",
			expected: "This is a quote Second line\n",
		},
		{
			name:     "excessive blank lines collapsed",
			input:    "Line 1\n\n\n\n\nLine 2\n",
			expected: "Line 1\n\nLine 2\n",
		},
		{
			name:     "bullet list preserved",
			input:    "- Item 1\n- Item 2\n- Item 3\n",
			expected: "- Item 1\n- Item 2\n- Item 3\n",
		},
		{
			name:     "combined formatting",
			input:    "# Report\n\n**Status**: `active`\n\n| Key | Val |\n|-----|-----|\n| a   | b   |\n\n---\n\n> [!NOTE]\n> Check [docs](https://example.com)\n",
			expected: "Report\n\nStatus: active\n\nKey\tVal\na\tb\n\nNOTE:\nCheck docs (https://example.com)\n",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := stripMarkdownFormatting(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractTablesWithPlaceholders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		input            string
		expectedHTML     string
		expectedReplaces []string
	}{
		{
			name:             "simple table",
			input:            `<table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table>`,
			expectedHTML:     `<p>OPNDOSSIER_PH_0</p>`,
			expectedReplaces: []string{"A\tB\n1\t2"},
		},
		{
			name:             "no tables",
			input:            `<p>No tables here</p>`,
			expectedHTML:     `<p>No tables here</p>`,
			expectedReplaces: nil,
		},
		{
			name:             "table with formatted cell content",
			input:            `<table><tr><td><strong>bold</strong></td><td>plain</td></tr></table>`,
			expectedHTML:     `<p>OPNDOSSIER_PH_0</p>`,
			expectedReplaces: []string{"bold\tplain"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var replacements []string
			counter := 0
			result := extractTablesWithPlaceholders(tt.input, &replacements, &counter)
			assert.Equal(t, tt.expectedHTML, result)
			assert.Equal(t, tt.expectedReplaces, replacements)
		})
	}
}

func TestExtractAlertsWithPlaceholders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		input            string
		expectedHTML     string
		expectedReplaces []string
	}{
		{
			name:             "warning alert",
			input:            "<blockquote>\n<p>[!WARNING]<br />\nBe careful.</p>\n</blockquote>",
			expectedHTML:     "<p>OPNDOSSIER_PH_0</p>",
			expectedReplaces: []string{"WARNING:\nBe careful."},
		},
		{
			name:             "regular blockquote unchanged",
			input:            "<blockquote>\n<p>Just a quote.</p>\n</blockquote>",
			expectedHTML:     "<blockquote>\n<p>Just a quote.</p>\n</blockquote>",
			expectedReplaces: nil,
		},
		{
			name:             "note alert",
			input:            "<blockquote>\n<p>[!NOTE]<br />\nSome info.</p>\n</blockquote>",
			expectedHTML:     "<p>OPNDOSSIER_PH_0</p>",
			expectedReplaces: []string{"NOTE:\nSome info."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var replacements []string
			counter := 0
			result := extractAlertsWithPlaceholders(tt.input, &replacements, &counter)
			assert.Equal(t, tt.expectedHTML, result)
			assert.Equal(t, tt.expectedReplaces, replacements)
		})
	}
}

func TestConvertLinksToPlainText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple link",
			input:    `<a href="https://example.com">Example</a>`,
			expected: "Example (https://example.com)",
		},
		{
			name:     "no links",
			input:    "<p>No links here</p>",
			expected: "<p>No links here</p>",
		},
		{
			name:     "multiple links",
			input:    `<a href="https://a.com">A</a> and <a href="https://b.com">B</a>`,
			expected: "A (https://a.com) and B (https://b.com)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := convertLinksToPlainText(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTrimLineWhitespace(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "leading spaces removed",
			input:    " Heading\n Normal\n",
			expected: "Heading\nNormal\n",
		},
		{
			name:     "trailing spaces removed",
			input:    "- Item 1 \n- Item 2 \n",
			expected: "- Item 1\n- Item 2\n",
		},
		{
			name:     "tabs in middle preserved",
			input:    "Name\tValue\nfoo\tbar\n",
			expected: "Name\tValue\nfoo\tbar\n",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := trimLineWhitespace(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHybridGenerator_GeneratePlainText(t *testing.T) {
	t.Parallel()

	reportBuilder := builder.NewMarkdownBuilder()
	gen, err := NewHybridGenerator(reportBuilder, nil)
	require.NoError(t, err)

	doc := &common.CommonDevice{}
	opts := DefaultOptions().WithFormat(FormatText)

	output, err := gen.Generate(context.Background(), doc, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, output)

	// Plain text output should not contain markdown formatting
	assert.NotContains(t, output, "# ")
	assert.NotContains(t, output, "**")
	assert.NotContains(t, output, "](")
}

func TestHybridGenerator_GeneratePlainTextToWriter(t *testing.T) {
	t.Parallel()

	reportBuilder := builder.NewMarkdownBuilder()
	gen, err := NewHybridGenerator(reportBuilder, nil)
	require.NoError(t, err)

	doc := &common.CommonDevice{}
	opts := DefaultOptions().WithFormat(FormatText)

	var buf bytes.Buffer
	err = gen.GenerateToWriter(context.Background(), &buf, doc, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, buf.String())

	// Should produce same output as Generate
	directOutput, err := gen.Generate(context.Background(), doc, opts)
	require.NoError(t, err)
	assert.Equal(t, directOutput, buf.String())
}

func TestHybridGenerator_GeneratePlainText_NilConfig(t *testing.T) {
	t.Parallel()

	reportBuilder := builder.NewMarkdownBuilder()
	gen, err := NewHybridGenerator(reportBuilder, nil)
	require.NoError(t, err)

	opts := DefaultOptions().WithFormat(FormatText)
	_, err = gen.Generate(context.Background(), nil, opts)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilDevice)
}

func TestFormatText_Validate(t *testing.T) {
	t.Parallel()
	err := FormatText.Validate()
	require.NoError(t, err)
}

func TestFormatText_String(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "text", FormatText.String())
}
