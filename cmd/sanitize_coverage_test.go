package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDetermineSanitizeOutputPath verifies the sanitize output path logic
// for force mode, nonexistent files, and existing files.
func TestDetermineSanitizeOutputPath(t *testing.T) {
	t.Run("nonexistent file returns path unchanged", func(t *testing.T) {
		tmpDir := t.TempDir()
		outPath := tmpDir + "/nonexistent-output.xml"

		result, err := determineSanitizeOutputPath(outPath, false)
		require.NoError(t, err)
		assert.Equal(t, outPath, result)
	})

	t.Run("force mode returns path even when file exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		outPath := tmpDir + "/existing.xml"
		require.NoError(t, os.WriteFile(outPath, []byte("<root/>"), 0o600))

		result, err := determineSanitizeOutputPath(outPath, true)
		require.NoError(t, err)
		assert.Equal(t, outPath, result)
	})

	t.Run("existing file without force returns cancelled error on stdin N", func(t *testing.T) {
		tmpDir := t.TempDir()
		outPath := tmpDir + "/existing.xml"
		require.NoError(t, os.WriteFile(outPath, []byte("<root/>"), 0o600))

		// Simulate user typing "N\n" on stdin
		origStdin := os.Stdin
		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdin = r
		t.Cleanup(func() { os.Stdin = origStdin })

		_, writeErr := w.WriteString("N\n")
		require.NoError(t, writeErr)
		require.NoError(t, w.Close())

		_, err = determineSanitizeOutputPath(outPath, false)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrOperationCancelled)
	})

	t.Run("existing file without force returns cancelled on empty response", func(t *testing.T) {
		tmpDir := t.TempDir()
		outPath := tmpDir + "/existing.xml"
		require.NoError(t, os.WriteFile(outPath, []byte("<root/>"), 0o600))

		// Simulate user pressing Enter (empty response = "N")
		origStdin := os.Stdin
		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdin = r
		t.Cleanup(func() { os.Stdin = origStdin })

		_, writeErr := w.WriteString("\n")
		require.NoError(t, writeErr)
		require.NoError(t, w.Close())

		_, err = determineSanitizeOutputPath(outPath, false)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrOperationCancelled)
	})

	t.Run("existing file with user confirming y proceeds", func(t *testing.T) {
		tmpDir := t.TempDir()
		outPath := tmpDir + "/existing.xml"
		require.NoError(t, os.WriteFile(outPath, []byte("<root/>"), 0o600))

		// Simulate user typing "y\n" on stdin
		origStdin := os.Stdin
		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdin = r
		t.Cleanup(func() { os.Stdin = origStdin })

		_, writeErr := w.WriteString("y\n")
		require.NoError(t, writeErr)
		require.NoError(t, w.Close())

		result, err := determineSanitizeOutputPath(outPath, false)
		require.NoError(t, err)
		assert.Equal(t, outPath, result)
	})
}
