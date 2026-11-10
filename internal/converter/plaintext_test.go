package converter

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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
			result, err := StripMarkdownFormatting(tt.input)
			require.NoError(t, err)
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
			expectedHTML:     `<p>OPNDOSSIER_PH_0_END</p>`,
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
			expectedHTML:     `<p>OPNDOSSIER_PH_0_END</p>`,
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
			expectedHTML:     "<p>OPNDOSSIER_PH_0_END</p>",
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
			expectedHTML:     "<p>OPNDOSSIER_PH_0_END</p>",
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

// TestStripMarkdownFormatting_NestedLists pins that a nested list keeps its
// hierarchy in the text format. html2text flattens every <li> to one prefix,
// so the pipeline renders a list with nesting itself and keeps its indentation
// through the whitespace trim. A flat list still goes through html2text and
// reads as before.
func TestStripMarkdownFormatting_NestedLists(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "flat list unchanged",
			input:    "- a\n- b\n",
			expected: "- a\n- b\n",
		},
		{
			name:     "two levels",
			input:    "- **parent**\n  - child one\n  - child two\n- **other**\n  - child three\n",
			expected: "- parent\n  - child one\n  - child two\n- other\n  - child three\n",
		},
		{
			name:     "three levels",
			input:    "- a\n  - b\n    - c\n  - d\n- e\n",
			expected: "- a\n  - b\n    - c\n  - d\n- e\n",
		},
		{
			name:     "ordered list nested in a bullet list",
			input:    "- a\n  1. first\n  2. second\n",
			expected: "- a\n  - first\n  - second\n",
		},
		{
			name:     "inline markup and entities inside items",
			input:    "- *em* and [link](https://example.com)\n  - Services &gt; Setup\n",
			expected: "- em and link (https://example.com)\n  - Services > Setup\n",
		},
		{
			name:     "heading and paragraph around the list",
			input:    "### Recommendations\n- a\n  - b\n\nAfter.\n",
			expected: "Recommendations\n\n- a\n  - b\n\nAfter.\n",
		},
		{
			name:     "continuation paragraph after a nested list stays with its item",
			input:    "- parent\n  - child\n\n  continuation of parent\n- next\n",
			expected: "- parent\n  - child\n  continuation of parent\n- next\n",
		},
		{
			name:     "continuation paragraph at the second level",
			input:    "- a\n  - b\n    - c\n\n    after c\n",
			expected: "- a\n  - b\n    - c\n    after c\n",
		},
		// The cases below hold several placeholders in one document, so a
		// slip in the restore order or in the index alignment of the shared
		// replacements slice shows up here.
		{
			name:     "two nested lists separated by a paragraph",
			input:    "- a\n  - b\n\nBetween.\n\n- c\n  - d\n",
			expected: "- a\n  - b\n\nBetween.\n\n- c\n  - d\n",
		},
		{
			name:     "table followed by a nested list",
			input:    "| a | b |\n|---|---|\n| 1 | 2 |\n\n- parent\n  - child\n",
			expected: "a\tb\n1\t2\n\n- parent\n  - child\n",
		},
		{
			name:     "alert, nested list and table in one document",
			input:    "> [!NOTE]\n> Careful.\n\n- a\n  - b\n\n| x | y |\n|---|---|\n| 3 | 4 |\n",
			expected: "NOTE:\nCareful.\n\n- a\n  - b\n\nx\ty\n3\t4\n",
		},
		{
			// The table is extracted first, so its placeholder sits inside the
			// list's replacement and is restored by the second pass, at the
			// item's indentation.
			name:     "table inside an item that also has a nested list",
			input:    "- parent\n  - child\n\n  | a | b |\n  |---|---|\n  | 1 | 2 |\n- next\n",
			expected: "- parent\n  - child\n  a\tb\n  1\t2\n- next\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := StripMarkdownFormatting(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestStripMarkdownFormatting_ManyPlaceholders pins that placeholder indices
// do not collide once a document holds more than ten of them. A nested list
// is extracted after the tables, so it gets index 10, whose marker the marker
// for index 1 matched as a prefix: the list vanished, the first table was
// restored twice and a stray "0" was left behind.
func TestStripMarkdownFormatting_ManyPlaceholders(t *testing.T) {
	t.Parallel()

	var input, expected strings.Builder
	input.WriteString("- parent\n  - child\n\n")
	expected.WriteString("- parent\n  - child\n\n")
	for i := range 10 {
		fmt.Fprintf(&input, "| h%d |\n|---|\n| v%d |\n\n", i, i)
		fmt.Fprintf(&expected, "h%d\nv%d\n\n", i, i)
	}

	result, err := StripMarkdownFormatting(input.String())
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(expected.String())+"\n", result)
}

// TestStripMarkdownFormatting_AuditRecommendations passes the recommendations
// the audit builder renders through the text pipeline and checks that each
// component's recommendations stay nested under it (#993 review).
func TestStripMarkdownFormatting_AuditRecommendations(t *testing.T) {
	t.Parallel()

	section := builder.NewMarkdownBuilder().BuildAuditSection(&common.CommonDevice{
		ComplianceResults: &common.ComplianceResults{
			Mode: "blue",
			Metadata: map[string]any{
				"recommendations": []audit.Recommendation{
					{
						Component:       "backup-config",
						Recommendations: []string{"Enable AutoConfigBackup in Services > Auto Config Backup"},
					},
					{Component: "dns-config", Recommendations: []string{"Configure DNS servers", "Enable DNSSEC"}},
				},
			},
		},
	})

	text, err := StripMarkdownFormatting(section)
	require.NoError(t, err)
	assert.Contains(t, text,
		"Recommendations\n\n"+
			"- backup-config\n"+
			"  - Enable AutoConfigBackup in Services > Auto Config Backup\n"+
			"- dns-config\n"+
			"  - Configure DNS servers\n"+
			"  - Enable DNSSEC\n")
}

func TestHybridGenerator_GeneratePlainText(t *testing.T) {
	t.Parallel()

	reportBuilder := builder.NewMarkdownBuilder()
	gen, err := NewHybridGenerator(reportBuilder, nil)
	require.NoError(t, err)

	doc := &common.CommonDevice{}
	opts := DefaultOptions()
	opts.Format = FormatText
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
	opts := DefaultOptions()
	opts.Format = FormatText
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

	opts := DefaultOptions()
	opts.Format = FormatText
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
