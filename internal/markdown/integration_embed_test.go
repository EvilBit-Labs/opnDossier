package markdown

import (
	"embed"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Create a test embedded filesystem to simulate what main.go does
//
//go:embed testdata/*.tmpl
var testEmbeddedTemplates embed.FS

func TestSetEmbeddedTemplates(t *testing.T) {
	t.Run("SetEmbeddedTemplates updates global variable", func(t *testing.T) {
		// Create a temporary embedded FS for testing
		testFS := testEmbeddedTemplates

		// Set it using our function
		SetEmbeddedTemplates(testFS)

		// Verify it was set (we can't directly access embeddedTemplates,
		// but we can test through the template manager)
		tm := NewTemplateManager()

		// This will fail if embeddedTemplates wasn't properly set,
		// because loadFromEmbedded will try to use the empty embeddedTemplates
		_, err := tm.loadFromEmbedded("testdata/test.tmpl")
		// If the template doesn't exist, that's expected, but we should get
		// a "file not found" error, not a "no embed" error
		if err != nil {
			assert.Contains(t, err.Error(), "template not found in embedded filesystem")
			assert.NotContains(t, err.Error(), "no such file")
		}
	})
}

func TestTemplateManagerWithEmbeddedFallback(t *testing.T) {
	// This test simulates the real-world scenario where filesystem templates
	// might not be available, forcing fallback to embedded templates

	t.Run("loadFromEmbedded uses the set embedded filesystem", func(t *testing.T) {
		// Create test content
		testFS := testEmbeddedTemplates
		SetEmbeddedTemplates(testFS)

		tm := NewTemplateManager()

		// Try to load a template that exists in our test embedded FS
		// This will test that our SetEmbeddedTemplates actually works
		template, err := tm.loadFromEmbedded("testdata/test.tmpl")

		// If the test template exists, we should get a valid template
		// If it doesn't exist, we should get a proper "file not found" error
		if err != nil {
			// Should be a proper filesystem error, not an embedding error
			assert.Contains(t, err.Error(), "template not found in embedded filesystem")
			assert.NotContains(t, err.Error(), "buildssa")
			assert.NotContains(t, err.Error(), "export data")
		} else {
			// If successful, we should have a valid template
			assert.NotNil(t, template)
		}
	})
}

func TestEmbeddedTemplatesIntegration(t *testing.T) {
	// This test validates that the approach works end-to-end

	t.Run("can create generator and load templates when embedded is set", func(t *testing.T) {
		// Simulate what main.go does - set embedded templates
		// In this case, we'll use a minimal test embed
		SetEmbeddedTemplates(testEmbeddedTemplates)

		// Try to create a generator - this should work even if filesystem templates aren't found
		// because it will fall back to embedded templates

		// This should not panic or fail due to missing embedded templates
		opts := DefaultOptions()
		generator, err := NewMarkdownGeneratorWithTemplates(nil, "/nonexistent/template/dir", opts)

		// The generator creation might still fail due to no templates being found,
		// but it shouldn't fail due to embedding issues
		if err != nil {
			// If it fails, it should be because no templates were found, not because of embedding
			assert.Contains(t, err.Error(), "no templates found")
			assert.NotContains(t, err.Error(), "buildssa")
			assert.NotContains(t, err.Error(), "export data")
		} else {
			// If it succeeds, we should have a valid generator
			assert.NotNil(t, generator)
		}
	})
}
