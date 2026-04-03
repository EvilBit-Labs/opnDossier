package cmd

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidXMLFiles verifies the shell completion function for XML file arguments.
func TestValidXMLFiles(t *testing.T) {
	t.Run("returns xml files in current directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		require.NoError(t, os.WriteFile(tmpDir+"/config.xml", []byte("<root/>"), 0o600))

		require.NoError(t, os.WriteFile(tmpDir+"/other.xml", []byte("<root/>"), 0o600))

		require.NoError(t, os.WriteFile(tmpDir+"/readme.md", []byte("# README"), 0o600))

		t.Chdir(tmpDir)

		completions, directive := ValidXMLFiles(nil, nil, "")
		assert.Equal(t, cobra.ShellCompDirectiveNoSpace, directive)
		assert.Contains(t, completions, "config.xml")
		assert.Contains(t, completions, "other.xml")
		assert.NotContains(t, completions, "readme.md")
	})

	t.Run("includes directories with trailing slash", func(t *testing.T) {
		tmpDir := t.TempDir()

		require.NoError(t, os.Mkdir(tmpDir+"/subdir", 0o755))

		require.NoError(t, os.WriteFile(tmpDir+"/config.xml", []byte("<root/>"), 0o600))

		t.Chdir(tmpDir)

		completions, _ := ValidXMLFiles(nil, nil, "")
		assert.Contains(t, completions, "subdir/")
	})

	t.Run("filters by prefix", func(t *testing.T) {
		tmpDir := t.TempDir()

		require.NoError(t, os.WriteFile(tmpDir+"/config.xml", []byte("<root/>"), 0o600))

		require.NoError(t, os.WriteFile(tmpDir+"/backup.xml", []byte("<root/>"), 0o600))

		t.Chdir(tmpDir)

		completions, _ := ValidXMLFiles(nil, nil, "con")
		assert.Contains(t, completions, "config.xml")
		assert.NotContains(t, completions, "backup.xml")
	})

	t.Run("skips hidden files", func(t *testing.T) {
		tmpDir := t.TempDir()

		require.NoError(t, os.WriteFile(tmpDir+"/.hidden.xml", []byte("<root/>"), 0o600))

		require.NoError(t, os.WriteFile(tmpDir+"/visible.xml", []byte("<root/>"), 0o600))

		t.Chdir(tmpDir)

		completions, _ := ValidXMLFiles(nil, nil, "")
		assert.Contains(t, completions, "visible.xml")
		assert.NotContains(t, completions, ".hidden.xml")
	})

	t.Run("returns default directive for nonexistent directory", func(t *testing.T) {
		completions, directive := ValidXMLFiles(nil, nil, "/nonexistent/path/")
		assert.Nil(t, completions)
		assert.Equal(t, cobra.ShellCompDirectiveDefault, directive)
	})

	t.Run("returns default directive when no matches", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Chdir(tmpDir)

		completions, directive := ValidXMLFiles(nil, nil, "")
		assert.Nil(t, completions)
		assert.Equal(t, cobra.ShellCompDirectiveDefault, directive)
	})

	t.Run("completes within subdirectory path", func(t *testing.T) {
		tmpDir := t.TempDir()
		subDir := tmpDir + "/configs"
		require.NoError(t, os.Mkdir(subDir, 0o755))

		require.NoError(t, os.WriteFile(subDir+"/test.xml", []byte("<root/>"), 0o600))

		completions, directive := ValidXMLFiles(nil, nil, subDir+"/")
		assert.Equal(t, cobra.ShellCompDirectiveNoSpace, directive)
		assert.Contains(t, completions, subDir+"/test.xml")
	})
}
