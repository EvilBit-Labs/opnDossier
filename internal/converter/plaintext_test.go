package converter

import (
	"bytes"
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
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
			expected: "Heading 1\nHeading 2\nHeading 3\n",
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
			expected: "Name\tValue\n\nfoo\tbar\n",
		},
		{
			name:     "alert marker conversion",
			input:    "> [!WARNING]\n> This is a warning\n",
			expected: "WARNING:\nThis is a warning\n",
		},
		{
			name:     "blockquote removal",
			input:    "> This is a quote\n> Second line\n",
			expected: "This is a quote\nSecond line\n",
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
			expected: "Report\n\nStatus: active\n\nKey\tVal\n\na\tb\n\nNOTE:\nCheck docs (https://example.com)\n",
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

func TestConvertTableRows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple table with separator removed",
			input:    "| A | B |\n|---|---|\n| 1 | 2 |\n",
			expected: "A\tB\n\n1\t2\n",
		},
		{
			name:     "non-table text unchanged",
			input:    "This is not a table\n",
			expected: "This is not a table\n",
		},
		{
			name:     "mixed content with table",
			input:    "Header\n| Col1 | Col2 |\n|------|------|\n| val  | val2 |\nFooter\n",
			expected: "Header\nCol1\tCol2\n\nval\tval2\nFooter\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := convertTableRows(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHybridGenerator_GeneratePlainText(t *testing.T) {
	t.Parallel()

	reportBuilder := builder.NewMarkdownBuilder()
	gen, err := NewHybridGenerator(reportBuilder, nil)
	require.NoError(t, err)

	doc := &model.OpnSenseDocument{}
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

	doc := &model.OpnSenseDocument{}
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
	assert.ErrorIs(t, err, ErrNilConfiguration)
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
