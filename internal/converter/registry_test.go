package converter

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

func TestFormatRegistry_RegisterNilHandlerPanics(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()

	assert.PanicsWithValue(t,
		`converter: nil handler for format "bogus"`,
		func() { r.Register("bogus", nil) },
		"Register with nil handler should panic",
	)
}

func TestFormatRegistry_RegisterDuplicateFormatPanics(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("markdown", &markdownHandler{})

	assert.PanicsWithValue(t,
		`converter: format "markdown" already registered`,
		func() { r.Register("markdown", &markdownHandler{}) },
		"Register with duplicate format should panic",
	)
}

func TestFormatRegistry_RegisterDuplicateAliasPanics(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("markdown", &markdownHandler{}) // registers alias "md"

	assert.PanicsWithValue(t,
		`converter: alias "md" already registered`,
		func() { r.Register("other", &markdownHandler{}) }, // also tries alias "md"
		"Register with conflicting alias should panic",
	)
}

func TestFormatRegistry_Get(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("markdown", &markdownHandler{})

	t.Run("canonical name", func(t *testing.T) {
		t.Parallel()

		h, err := r.Get("markdown")
		require.NoError(t, err)
		assert.Equal(t, ".md", h.FileExtension())
	})

	t.Run("alias", func(t *testing.T) {
		t.Parallel()

		h, err := r.Get("md")
		require.NoError(t, err)
		assert.Equal(t, ".md", h.FileExtension())
	})

	t.Run("unsupported format", func(t *testing.T) {
		t.Parallel()

		_, err := r.Get("nope")
		assert.ErrorIs(t, err, ErrUnsupportedFormat)
	})
}

func TestFormatRegistry_Canonical(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("yaml", &yamlHandler{})

	assert.Equal(t, "yaml", r.Canonical("yml"))
	assert.Equal(t, "yaml", r.Canonical("YAML"))
	assert.Equal(t, "unknown", r.Canonical("unknown"))
}

func TestFormatRegistry_ValidFormats(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("json", &jsonHandler{})
	r.Register("yaml", &yamlHandler{})

	formats := r.ValidFormats()
	assert.Equal(t, []string{"json", "yaml"}, formats)
}

func TestFormatRegistry_ValidFormatsWithAliases(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("yaml", &yamlHandler{})

	all := r.ValidFormatsWithAliases()
	assert.Equal(t, []string{"yaml", "yml"}, all)
}

func TestFormatRegistry_Extensions(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("json", &jsonHandler{})
	r.Register("html", &htmlHandler{})

	exts := r.Extensions()
	assert.Equal(t, ".json", exts["json"])
	assert.Equal(t, ".html", exts["html"])
}

// stubHandler is a minimal FormatHandler for testing registry mechanics without
// depending on real handler types.
type stubHandler struct {
	ext     string
	aliases []string
}

func (s *stubHandler) FileExtension() string { return s.ext }
func (s *stubHandler) Aliases() []string     { return s.aliases }

func (s *stubHandler) Generate(_ *HybridGenerator, _ *common.CommonDevice, _ Options) (string, error) {
	return "stub", nil
}

func (s *stubHandler) GenerateToWriter(_ *HybridGenerator, _ io.Writer, _ *common.CommonDevice, _ Options) error {
	return nil
}

func TestFormatRegistry_RegisterAliasConflictsWithCanonicalPanics(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	// Register "md" as a canonical format first.
	r.Register("md", &stubHandler{ext: ".md"})

	// Now register "markdown" whose alias is "md" -- should conflict with the canonical "md".
	assert.PanicsWithValue(t,
		`converter: alias "md" conflicts with canonical format`,
		func() { r.Register("markdown", &markdownHandler{}) },
		"Register with alias conflicting a canonical format should panic",
	)
}

func TestFormatRegistry_Get_CaseInsensitive(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("json", &jsonHandler{})

	tests := []struct {
		name   string
		input  string
		wantExt string
	}{
		{name: "uppercase", input: "JSON", wantExt: ".json"},
		{name: "mixed case", input: "Json", wantExt: ".json"},
		{name: "lowercase", input: "json", wantExt: ".json"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h, err := r.Get(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.wantExt, h.FileExtension())
		})
	}
}

func TestFormatRegistry_Get_AliasReturnsSameHandlerAsCanonical(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("yaml", &yamlHandler{})

	canonical, err := r.Get("yaml")
	require.NoError(t, err)

	alias, err := r.Get("yml")
	require.NoError(t, err)

	assert.Equal(t, canonical, alias, "alias and canonical should return the same handler instance")
}

func TestFormatRegistry_Canonical_CanonicalReturnsSelf(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("markdown", &markdownHandler{})
	r.Register("json", &jsonHandler{})

	assert.Equal(t, "markdown", r.Canonical("markdown"))
	assert.Equal(t, "json", r.Canonical("json"))
}

func TestFormatRegistry_Canonical_CaseInsensitive(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("html", &htmlHandler{})

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "uppercase canonical", input: "HTML", want: "html"},
		{name: "mixed case canonical", input: "Html", want: "html"},
		{name: "uppercase alias", input: "HTM", want: "html"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, r.Canonical(tc.input))
		})
	}
}

func TestFormatRegistry_ValidFormats_ExcludesAliases(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("text", &textHandler{})   // alias "txt"
	r.Register("yaml", &yamlHandler{})   // alias "yml"
	r.Register("html", &htmlHandler{})   // alias "htm"

	formats := r.ValidFormats()
	assert.Equal(t, []string{"html", "text", "yaml"}, formats)
	assert.NotContains(t, formats, "txt")
	assert.NotContains(t, formats, "yml")
	assert.NotContains(t, formats, "htm")
}

func TestFormatRegistry_ValidFormatsWithAliases_AllFormats(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("markdown", &markdownHandler{}) // alias "md"
	r.Register("json", &jsonHandler{})          // no alias
	r.Register("yaml", &yamlHandler{})          // alias "yml"

	all := r.ValidFormatsWithAliases()
	assert.Equal(t, []string{"json", "markdown", "md", "yaml", "yml"}, all)
}

func TestFormatRegistry_Extensions_AllFormats(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("markdown", &markdownHandler{})
	r.Register("json", &jsonHandler{})
	r.Register("yaml", &yamlHandler{})
	r.Register("text", &textHandler{})
	r.Register("html", &htmlHandler{})

	exts := r.Extensions()
	assert.Len(t, exts, 5)
	assert.Equal(t, ".md", exts["markdown"])
	assert.Equal(t, ".json", exts["json"])
	assert.Equal(t, ".yaml", exts["yaml"])
	assert.Equal(t, ".txt", exts["text"])
	assert.Equal(t, ".html", exts["html"])
}

func TestFormatRegistry_Extensions_DoesNotIncludeAliases(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("yaml", &yamlHandler{})

	exts := r.Extensions()
	assert.Len(t, exts, 1)
	_, hasAlias := exts["yml"]
	assert.False(t, hasAlias, "aliases should not appear as keys in Extensions")
}

func TestFormatRegistry_EmptyRegistry(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()

	t.Run("Get returns error", func(t *testing.T) {
		t.Parallel()

		_, err := r.Get("anything")
		assert.ErrorIs(t, err, ErrUnsupportedFormat)
	})

	t.Run("Canonical returns lowercased input", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "anything", r.Canonical("ANYTHING"))
	})

	t.Run("ValidFormats returns empty slice", func(t *testing.T) {
		t.Parallel()

		formats := r.ValidFormats()
		assert.Empty(t, formats)
	})

	t.Run("ValidFormatsWithAliases returns empty slice", func(t *testing.T) {
		t.Parallel()

		all := r.ValidFormatsWithAliases()
		assert.Empty(t, all)
	})

	t.Run("Extensions returns empty map", func(t *testing.T) {
		t.Parallel()

		exts := r.Extensions()
		assert.Empty(t, exts)
	})
}

// --- DefaultRegistry content verification ---

func TestDefaultRegistry_ContainsFiveFormats(t *testing.T) {
	t.Parallel()

	formats := DefaultRegistry.ValidFormats()
	assert.Equal(t, []string{"html", "json", "markdown", "text", "yaml"}, formats)
}

func TestDefaultRegistry_CorrectExtensions(t *testing.T) {
	t.Parallel()

	expected := map[string]string{
		"markdown": ".md",
		"json":     ".json",
		"yaml":     ".yaml",
		"text":     ".txt",
		"html":     ".html",
	}

	exts := DefaultRegistry.Extensions()
	assert.Equal(t, expected, exts)
}

func TestDefaultRegistry_CorrectAliases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		alias     string
		canonical string
	}{
		{alias: "md", canonical: "markdown"},
		{alias: "yml", canonical: "yaml"},
		{alias: "txt", canonical: "text"},
		{alias: "htm", canonical: "html"},
	}

	for _, tc := range tests {
		t.Run(tc.alias, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.canonical, DefaultRegistry.Canonical(tc.alias))

			h, err := DefaultRegistry.Get(tc.alias)
			require.NoError(t, err)

			canonicalHandler, err := DefaultRegistry.Get(tc.canonical)
			require.NoError(t, err)
			assert.Equal(t, canonicalHandler, h, "alias should resolve to the same handler as canonical")
		})
	}
}

func TestDefaultRegistry_JSONHasNoAliases(t *testing.T) {
	t.Parallel()

	// JSON has no aliases; verify "json" is not returned as an alias of anything else,
	// and that common misspellings are unsupported.
	_, err := DefaultRegistry.Get("jsn")
	assert.ErrorIs(t, err, ErrUnsupportedFormat)
}

func TestDefaultRegistry_ValidFormatsWithAliases(t *testing.T) {
	t.Parallel()

	all := DefaultRegistry.ValidFormatsWithAliases()
	expected := []string{"htm", "html", "json", "markdown", "md", "text", "txt", "yaml", "yml"}
	assert.Equal(t, expected, all)
}

// --- handlerForFormat tests ---

func TestHandlerForFormat_EmptyDefaultsToMarkdown(t *testing.T) {
	t.Parallel()

	h, err := handlerForFormat("")
	require.NoError(t, err)
	assert.Equal(t, ".md", h.FileExtension())
}

func TestHandlerForFormat_KnownFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		format  string
		wantExt string
	}{
		{format: "markdown", wantExt: ".md"},
		{format: "json", wantExt: ".json"},
		{format: "yaml", wantExt: ".yaml"},
		{format: "text", wantExt: ".txt"},
		{format: "html", wantExt: ".html"},
	}

	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			t.Parallel()

			h, err := handlerForFormat(tc.format)
			require.NoError(t, err)
			assert.Equal(t, tc.wantExt, h.FileExtension())
		})
	}
}

func TestHandlerForFormat_Alias(t *testing.T) {
	t.Parallel()

	h, err := handlerForFormat("yml")
	require.NoError(t, err)
	assert.Equal(t, ".yaml", h.FileExtension())
}

func TestHandlerForFormat_UnknownFormat(t *testing.T) {
	t.Parallel()

	_, err := handlerForFormat("docx")
	assert.ErrorIs(t, err, ErrUnsupportedFormat)
}

// --- Handler metadata verification ---

func TestHandlers_FileExtensions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler FormatHandler
		wantExt string
	}{
		{name: "markdown", handler: &markdownHandler{}, wantExt: ".md"},
		{name: "json", handler: &jsonHandler{}, wantExt: ".json"},
		{name: "yaml", handler: &yamlHandler{}, wantExt: ".yaml"},
		{name: "text", handler: &textHandler{}, wantExt: ".txt"},
		{name: "html", handler: &htmlHandler{}, wantExt: ".html"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.wantExt, tc.handler.FileExtension())
		})
	}
}

func TestHandlers_Aliases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		handler     FormatHandler
		wantAliases []string
	}{
		{name: "markdown", handler: &markdownHandler{}, wantAliases: []string{"md"}},
		{name: "json", handler: &jsonHandler{}, wantAliases: nil},
		{name: "yaml", handler: &yamlHandler{}, wantAliases: []string{"yml"}},
		{name: "text", handler: &textHandler{}, wantAliases: []string{"txt"}},
		{name: "html", handler: &htmlHandler{}, wantAliases: []string{"htm"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.wantAliases, tc.handler.Aliases())
		})
	}
}

// --- Register edge cases ---

func TestFormatRegistry_Register_CaseInsensitiveCanonical(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("JSON", &jsonHandler{})

	// Should be stored lowercase and retrievable case-insensitively.
	h, err := r.Get("json")
	require.NoError(t, err)
	assert.Equal(t, ".json", h.FileExtension())

	h2, err := r.Get("JSON")
	require.NoError(t, err)
	assert.Equal(t, h, h2)
}

func TestFormatRegistry_Register_NoAliases(t *testing.T) {
	t.Parallel()

	r := NewFormatRegistry()
	r.Register("json", &jsonHandler{}) // jsonHandler has nil aliases

	formats := r.ValidFormats()
	assert.Equal(t, []string{"json"}, formats)

	all := r.ValidFormatsWithAliases()
	assert.Equal(t, []string{"json"}, all)
}
