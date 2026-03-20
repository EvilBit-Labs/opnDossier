package converter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
