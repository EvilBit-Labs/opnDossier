// Package main tests for the embedded templates functionality.
// These tests validate that templates are properly embedded at compile time
// and accessible through the EmbeddedTemplates variable in main.go.
package main

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedTemplates(t *testing.T) {
	t.Run("embedded filesystem is accessible", func(t *testing.T) {
		// Test that we can access the embedded FS
		entries, err := fs.ReadDir(EmbeddedTemplates, "internal/templates")
		require.NoError(t, err)
		assert.NotEmpty(t, entries, "embedded templates directory should not be empty")
	})

	t.Run("required template files are embedded", func(t *testing.T) {
		expectedTemplates := []string{
			"internal/templates/opnsense_report.md.tmpl",
			"internal/templates/opnsense_report_comprehensive.md.tmpl",
			"internal/templates/reports/blue.md.tmpl",
			"internal/templates/reports/red.md.tmpl",
			"internal/templates/reports/standard.md.tmpl",
			"internal/templates/reports/blue_enhanced.md.tmpl",
		}

		for _, template := range expectedTemplates {
			t.Run(filepath.Base(template), func(t *testing.T) {
				// Test that the file exists in embedded FS
				_, err := EmbeddedTemplates.Open(template)
				require.NoError(t, err, "template %s should be embedded", template)

				// Test that we can read the content
				content, err := EmbeddedTemplates.ReadFile(template)
				require.NoError(t, err)
				assert.NotEmpty(t, content, "template %s should not be empty", template)

				// Test that it looks like a template (contains template syntax)
				contentStr := string(content)
				assert.Greater(t,
					len(contentStr), 10,
					"template %s should have reasonable content length", template)
			})
		}
	})

	t.Run("embedded content matches filesystem content", func(t *testing.T) {
		// Test a few key templates to ensure embedded content matches filesystem
		testTemplates := []string{
			"internal/templates/opnsense_report.md.tmpl",
			"internal/templates/reports/blue.md.tmpl",
		}

		for _, template := range testTemplates {
			t.Run(filepath.Base(template), func(t *testing.T) {
				// Read from embedded FS
				embeddedContent, err := EmbeddedTemplates.ReadFile(template)
				require.NoError(t, err)

				// Read from filesystem
				fsContent, err := fs.ReadFile(EmbeddedTemplates, template)
				require.NoError(t, err)

				// They should be identical
				assert.Equal(t, fsContent, embeddedContent,
					"embedded content should match filesystem content for %s", template)
			})
		}
	})

	t.Run("can walk embedded filesystem", func(t *testing.T) {
		var foundFiles []string

		err := fs.WalkDir(EmbeddedTemplates, "internal/templates", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && filepath.Ext(path) == ".tmpl" {
				foundFiles = append(foundFiles, path)
			}
			return nil
		})

		require.NoError(t, err)
		assert.NotEmpty(t, foundFiles, "should find template files when walking embedded FS")

		// Verify we found expected number of templates
		assert.GreaterOrEqual(t, len(foundFiles), 4, "should find at least 4 template files")
	})

	t.Run("embedded templates contain expected template syntax", func(t *testing.T) {
		// Test that templates contain Go template syntax
		content, err := EmbeddedTemplates.ReadFile("internal/templates/opnsense_report.md.tmpl")
		require.NoError(t, err)

		contentStr := string(content)

		// Should contain template syntax
		assert.Contains(t, contentStr, "{{", "template should contain Go template syntax")
		assert.Contains(t, contentStr, "}}", "template should contain Go template syntax")
	})
}

func TestEmbeddedTemplatesGlobbing(t *testing.T) {
	t.Run("can glob template files", func(t *testing.T) {
		// Test globbing functionality
		matches, err := fs.Glob(EmbeddedTemplates, "internal/templates/*.tmpl")
		require.NoError(t, err)
		assert.NotEmpty(t, matches, "should find template files with glob pattern")

		// Test reports subdirectory
		reportMatches, err := fs.Glob(EmbeddedTemplates, "internal/templates/reports/*.tmpl")
		require.NoError(t, err)
		assert.NotEmpty(t, reportMatches, "should find report template files with glob pattern")
	})

	t.Run("glob patterns match expected files", func(t *testing.T) {
		// Test specific patterns that the markdown generator uses
		patterns := []struct {
			pattern  string
			minFiles int
		}{
			{"internal/templates/*.tmpl", 2},         // Main templates
			{"internal/templates/reports/*.tmpl", 4}, // Report templates
		}

		for _, p := range patterns {
			t.Run(p.pattern, func(t *testing.T) {
				matches, err := fs.Glob(EmbeddedTemplates, p.pattern)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(matches), p.minFiles,
					"pattern %s should match at least %d files", p.pattern, p.minFiles)
			})
		}
	})
}
