package converter

import (
	"bytes"
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHybridGenerator(t *testing.T) {
	t.Parallel()

	t.Run("with logger", func(t *testing.T) {
		t.Parallel()
		logger, err := logging.New(logging.Config{})
		require.NoError(t, err)
		gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), logger)
		require.NoError(t, err)
		assert.NotNil(t, gen)
	})

	t.Run("nil logger creates default", func(t *testing.T) {
		t.Parallel()
		gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
		require.NoError(t, err)
		assert.NotNil(t, gen)
	})
}

func TestNewMarkdownGenerator(t *testing.T) {
	t.Parallel()

	t.Run("with nil logger", func(t *testing.T) {
		t.Parallel()
		gen, err := NewMarkdownGenerator(nil, DefaultOptions())
		require.NoError(t, err)
		assert.NotNil(t, gen)
	})

	t.Run("with provided logger", func(t *testing.T) {
		t.Parallel()
		logger, err := logging.New(logging.Config{})
		require.NoError(t, err)
		gen, err := NewMarkdownGenerator(logger, DefaultOptions())
		require.NoError(t, err)
		assert.NotNil(t, gen)
	})
}

func TestEnsureLogger(t *testing.T) {
	t.Parallel()

	t.Run("nil logger creates default", func(t *testing.T) {
		t.Parallel()
		logger, err := ensureLogger(nil)
		require.NoError(t, err)
		assert.NotNil(t, logger)
	})

	t.Run("non-nil logger returned as-is", func(t *testing.T) {
		t.Parallel()
		original, err := logging.New(logging.Config{})
		require.NoError(t, err)
		returned, err := ensureLogger(original)
		require.NoError(t, err)
		assert.Same(t, original, returned)
	})
}

func TestHybridGenerator_SetGetBuilder(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	original := gen.GetBuilder()
	assert.NotNil(t, original)

	newBuilder := builder.NewMarkdownBuilder()
	gen.SetBuilder(newBuilder)
	assert.Same(t, newBuilder, gen.GetBuilder())
}

func TestHybridGenerator_GenerateHTML(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat(FormatHTML)

	output, err := gen.Generate(context.Background(), doc, opts)
	require.NoError(t, err)
	assert.Contains(t, output, "<!DOCTYPE html>")
	assert.Contains(t, output, "<body>")
	assert.Contains(t, output, "OPNsense Configuration Report")
}

func TestHybridGenerator_GenerateHTMLToWriter(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat(FormatHTML)

	var buf bytes.Buffer
	err = gen.GenerateToWriter(context.Background(), &buf, doc, opts)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "<!DOCTYPE html>")

	// Should match Generate output
	direct, err := gen.Generate(context.Background(), doc, opts)
	require.NoError(t, err)
	assert.Equal(t, direct, buf.String())
}

func TestHybridGenerator_GenerateJSON(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat(FormatJSON)

	output, err := gen.Generate(context.Background(), doc, opts)
	require.NoError(t, err)
	assert.Contains(t, output, "{")
	assert.Contains(t, output, "}")
}

func TestHybridGenerator_GenerateJSONToWriter(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat(FormatJSON)

	var buf bytes.Buffer
	err = gen.GenerateToWriter(context.Background(), &buf, doc, opts)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "{")
}

func TestHybridGenerator_GenerateYAML(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat(FormatYAML)

	output, err := gen.Generate(context.Background(), doc, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, output)
}

func TestHybridGenerator_GenerateYAMLToWriter(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat(FormatYAML)

	var buf bytes.Buffer
	err = gen.GenerateToWriter(context.Background(), &buf, doc, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, buf.String())
}

func TestHybridGenerator_GenerateMarkdownToWriter(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat(FormatMarkdown)

	var buf bytes.Buffer
	err = gen.GenerateToWriter(context.Background(), &buf, doc, opts)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "#")
}

func TestHybridGenerator_Generate_NilData(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		format Format
	}{
		{name: "markdown", format: FormatMarkdown},
		{name: "json", format: FormatJSON},
		{name: "yaml", format: FormatYAML},
		{name: "text", format: FormatText},
		{name: "html", format: FormatHTML},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions().WithFormat(tt.format)
			_, err := gen.Generate(context.Background(), nil, opts)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrNilConfiguration)
		})
	}
}

func TestHybridGenerator_GenerateToWriter_NilData(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		format Format
	}{
		{name: "markdown", format: FormatMarkdown},
		{name: "json", format: FormatJSON},
		{name: "yaml", format: FormatYAML},
		{name: "text", format: FormatText},
		{name: "html", format: FormatHTML},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			opts := DefaultOptions().WithFormat(tt.format)
			err := gen.GenerateToWriter(context.Background(), &buf, nil, opts)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrNilConfiguration)
		})
	}
}

func TestHybridGenerator_Generate_InvalidOptions(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat("invalid_format")

	_, err = gen.Generate(context.Background(), doc, opts)
	require.Error(t, err)
}

func TestHybridGenerator_GenerateToWriter_InvalidOptions(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat("invalid_format")

	var buf bytes.Buffer
	err = gen.GenerateToWriter(context.Background(), &buf, doc, opts)
	require.Error(t, err)
}

func TestHybridGenerator_Generate_NilBuilder(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	gen.SetBuilder(nil)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat(FormatMarkdown)

	_, err = gen.Generate(context.Background(), doc, opts)
	require.Error(t, err)
}

func TestHybridGenerator_GenerateToWriter_NilBuilder(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	gen.SetBuilder(nil)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat(FormatMarkdown)

	var buf bytes.Buffer
	err = gen.GenerateToWriter(context.Background(), &buf, doc, opts)
	require.Error(t, err)
}

// nonStreamingBuilder wraps a ReportBuilder to hide the SectionWriter
// interface, forcing the generateMarkdownToWriter fallback path.
type nonStreamingBuilder struct {
	builder.ReportBuilder
}

func TestHybridGenerator_GenerateMarkdownToWriter_FallbackPath(t *testing.T) {
	t.Parallel()

	// Wrap the real builder to hide SectionWriter interface
	wrapped := &nonStreamingBuilder{ReportBuilder: builder.NewMarkdownBuilder()}
	gen, err := NewHybridGenerator(wrapped, nil)
	require.NoError(t, err)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat(FormatMarkdown)

	var buf bytes.Buffer
	err = gen.GenerateToWriter(context.Background(), &buf, doc, opts)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "#")
}

func TestHybridGenerator_GenerateMarkdownToWriter_ComprehensiveStreaming(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)

	doc := &model.OpnSenseDocument{}
	opts := DefaultOptions().WithFormat(FormatMarkdown)
	opts.Comprehensive = true

	var buf bytes.Buffer
	err = gen.GenerateToWriter(context.Background(), &buf, doc, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, buf.String())
}

func TestHybridGenerator_Generate_UnsupportedFormat(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)
	doc := &model.OpnSenseDocument{}

	// Use a format that passes Validate() but isn't handled by Generate.
	// Currently all valid formats are handled, so test with an invalid one.
	opts := DefaultOptions().WithFormat("invalid")
	_, err = gen.Generate(context.Background(), doc, opts)
	require.Error(t, err)
}

func TestHybridGenerator_GenerateToWriter_UnsupportedFormat(t *testing.T) {
	t.Parallel()

	gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
	require.NoError(t, err)
	doc := &model.OpnSenseDocument{}

	opts := DefaultOptions().WithFormat("invalid")
	var buf bytes.Buffer
	err = gen.GenerateToWriter(context.Background(), &buf, doc, opts)
	require.Error(t, err)
}
