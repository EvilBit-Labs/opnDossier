package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLevenshteinDistance verifies the edit distance calculation used for
// fuzzy matching in command and flag suggestions.
func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		name string
		s1   string
		s2   string
		want int
	}{
		{"identical strings", "hello", "hello", 0},
		{"empty first", "", "hello", 5},
		{"empty second", "hello", "", 5},
		{"both empty", "", "", 0},
		{"single insertion", "cat", "cart", 1},
		{"single deletion", "cart", "cat", 1},
		{"single substitution", "cat", "bat", 1},
		{"two edits", "kitten", "mitten", 1},
		{"completely different", "abc", "xyz", 3},
		{"case sensitive", "ABC", "abc", 3},
		{"prefix match", "form", "format", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := levenshteinDistance(tt.s1, tt.s2)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestGetSuggestions verifies that GetSuggestions returns command suggestions
// for similar command names and falls back to flag suggestions.
func TestGetSuggestions(t *testing.T) {
	t.Run("returns nil when suggestions disabled", func(t *testing.T) {
		cmd := &cobra.Command{Use: "root", DisableSuggestions: true}
		got := GetSuggestions(cmd, "conver")
		assert.Nil(t, got)
	})

	t.Run("returns command suggestions for similar names", func(t *testing.T) {
		// Use the real root command which has subcommands registered
		root := GetRootCmd()

		got := GetSuggestions(root, "convrt")
		assert.Contains(t, got, "convert")
	})

	t.Run("falls back to flag suggestions when no command match", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("format", "", "output format")
		cmd.SuggestionsMinimumDistance = 2

		got := GetSuggestions(cmd, "--formt")
		assert.Contains(t, got, "--format")
	})

	t.Run("returns empty when nothing matches", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("format", "", "output format")
		cmd.SuggestionsMinimumDistance = 2

		got := GetSuggestions(cmd, "zzzzz")
		assert.Empty(t, got)
	})
}

// TestSuggestFlags verifies that suggestFlags returns flag name suggestions
// based on Levenshtein distance, including inherited flags.
func TestSuggestFlags(t *testing.T) {
	t.Run("strips leading dashes before matching", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("verbose", "", "verbose output")
		cmd.SuggestionsMinimumDistance = 2

		got := suggestFlags(cmd, "--verbos")
		assert.Contains(t, got, "--verbose")
	})

	t.Run("returns nil for empty input after stripping dashes", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("verbose", "", "verbose output")
		cmd.SuggestionsMinimumDistance = 2

		got := suggestFlags(cmd, "--")
		assert.Nil(t, got)
	})

	t.Run("matches inherited flags", func(t *testing.T) {
		parent := &cobra.Command{Use: "root"}
		parent.PersistentFlags().String("config", "", "config file")

		child := &cobra.Command{Use: "sub"}
		parent.AddCommand(child)
		child.SuggestionsMinimumDistance = 2

		got := suggestFlags(child, "confi")
		assert.Contains(t, got, "--config")
	})

	t.Run("deduplicates when flag appears in both local and inherited", func(t *testing.T) {
		parent := &cobra.Command{Use: "root"}
		parent.PersistentFlags().String("output", "", "output file")

		child := &cobra.Command{Use: "sub"}
		parent.AddCommand(child)
		child.SuggestionsMinimumDistance = 2

		got := suggestFlags(child, "outpu")
		count := 0
		for _, s := range got {
			if s == "--output" {
				count++
			}
		}
		assert.Equal(t, 1, count, "should not duplicate suggestions")
	})

	t.Run("results are sorted", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("format", "", "")
		cmd.Flags().String("force", "", "")
		cmd.SuggestionsMinimumDistance = 2

		got := suggestFlags(cmd, "forc")
		if len(got) > 1 {
			for i := 1; i < len(got); i++ {
				assert.LessOrEqual(t, got[i-1], got[i], "suggestions should be sorted")
			}
		}
	})
}

// TestGetFlagObjectsByCategory verifies that flags are grouped by their
// category annotation, with uncategorized flags defaulting to "other".
func TestGetFlagObjectsByCategory(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("format", "", "output format")
	cmd.Flags().String("output", "", "output file")
	cmd.Flags().String("verbose", "", "verbose mode")

	// Set category annotations
	require.NoError(t, cmd.Flags().SetAnnotation("format", "category", []string{"output"}))
	require.NoError(t, cmd.Flags().SetAnnotation("output", "category", []string{"output"}))
	// verbose has no category annotation

	categories := GetFlagObjectsByCategory(cmd)

	// output category should contain format and output flags
	require.Contains(t, categories, "output")
	assert.Len(t, categories["output"], 2)

	outputFlagNames := make([]string, 0, len(categories["output"]))
	for _, f := range categories["output"] {
		outputFlagNames = append(outputFlagNames, f.Name)
	}
	assert.Contains(t, outputFlagNames, "format")
	assert.Contains(t, outputFlagNames, "output")

	// verbose should be in "other" category
	require.Contains(t, categories, "other")
	otherFlagNames := make([]string, 0, len(categories["other"]))
	for _, f := range categories["other"] {
		otherFlagNames = append(otherFlagNames, f.Name)
	}
	assert.Contains(t, otherFlagNames, "verbose")
}

// TestFormatExamples verifies that FormatExamples consistently formats
// command examples with proper indentation.
func TestFormatExamples(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty input", "", ""},
		{
			"comments get 2-space indent",
			"# Convert a config file",
			"  # Convert a config file",
		},
		{
			"commands get 4-space indent",
			"opnDossier convert config.xml",
			"    opnDossier convert config.xml",
		},
		{
			"blank lines preserved",
			"# Example\n\nopnDossier convert config.xml",
			"  # Example\n\n    opnDossier convert config.xml",
		},
		{
			"leading whitespace is stripped then re-indented",
			"    opnDossier convert config.xml",
			"    opnDossier convert config.xml",
		},
		{
			"mixed comments and commands",
			"# Step 1\nopnDossier validate config.xml\n\n# Step 2\nopnDossier convert config.xml",
			"  # Step 1\n    opnDossier validate config.xml\n\n  # Step 2\n    opnDossier convert config.xml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatExamples(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
