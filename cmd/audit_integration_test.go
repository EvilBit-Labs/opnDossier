package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAuditModeBlue  = "blue"
	testAuditModeRed   = "red"
	testFormatMarkdown = "markdown"
	testFormatJSON     = "json"
)

// TestRunAuditWithRealXML exercises the full runAudit pipeline with a real
// XML test fixture. This covers runAudit, generateAuditOutput, and
// emitAuditResult (stdout path). Uses JSON format because markdown
// renders through glamour to os.Stdout, bypassing cmd.OutOrStdout().
func TestRunAuditWithRealXML(t *testing.T) {
	testdataPath := filepath.Join("..", "testdata", "sample.config.1.xml")
	if _, err := os.Stat(testdataPath); os.IsNotExist(err) {
		t.Fatal("required testdata not available — ensure testdata/ is checked out")
	}

	auditSnap := captureAuditFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		auditSnap.restore()
		sharedSnap.restore()
	})

	// Set audit-specific flags — use JSON format to capture in buffer
	auditMode = testAuditModeBlue
	auditPlugins = []string{}
	auditPluginDir = ""
	auditFailuresOnly = false
	format = testFormatJSON
	outputFile = ""
	force = false

	testLogger, err := logging.New(logging.Config{Level: "error"})
	require.NoError(t, err)

	cfg := &config.Config{
		Format: testFormatJSON,
	}

	var stdout bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&stdout)
	cmd.SetContext(context.Background())
	SetCommandContext(cmd, &CommandContext{
		Config: cfg,
		Logger: testLogger,
	})

	cmd.Flags().StringVar(&format, "format", testFormatJSON, "")
	cmd.Flags().StringVar(&outputFile, "output", "", "")

	err = runAudit(cmd, []string{testdataPath})
	require.NoError(t, err)

	output := stdout.String()
	assert.NotEmpty(t, output, "audit should produce JSON output")
	// Verify it's well-formed JSON
	assert.True(t, json.Valid([]byte(output)), "output should be valid JSON")
}

// TestRunAuditMissingFile verifies that runAudit returns an error when
// the input file does not exist.
func TestRunAuditMissingFile(t *testing.T) {
	auditSnap := captureAuditFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		auditSnap.restore()
		sharedSnap.restore()
	})

	auditMode = testAuditModeBlue
	format = testFormatMarkdown
	outputFile = ""

	testLogger, err := logging.New(logging.Config{Level: "error"})
	require.NoError(t, err)

	cfg := &config.Config{
		Format: testFormatMarkdown,
	}

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())
	SetCommandContext(cmd, &CommandContext{
		Config: cfg,
		Logger: testLogger,
	})

	err = runAudit(cmd, []string{"/nonexistent/file.xml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}

// TestRunAuditNilContext verifies that runAudit returns an error when
// the command context is not initialized.
func TestRunAuditNilContext(t *testing.T) {
	auditSnap := captureAuditFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		auditSnap.restore()
		sharedSnap.restore()
	})

	auditMode = testAuditModeBlue
	sharedDeviceType = ""

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())
	// Don't set CommandContext

	err := runAudit(cmd, []string{"dummy.xml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "command context not initialized")
}

// TestRunAuditFileOutput verifies that runAudit writes to a file when
// the --output flag is set.
func TestRunAuditFileOutput(t *testing.T) {
	testdataPath := filepath.Join("..", "testdata", "sample.config.1.xml")
	if _, err := os.Stat(testdataPath); os.IsNotExist(err) {
		t.Fatal("required testdata not available — ensure testdata/ is checked out")
	}

	auditSnap := captureAuditFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		auditSnap.restore()
		sharedSnap.restore()
	})

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "audit-output.md")

	auditMode = testAuditModeBlue
	auditPlugins = []string{}
	format = testFormatMarkdown
	outputFile = outFile
	force = true

	testLogger, err := logging.New(logging.Config{Level: "error"})
	require.NoError(t, err)

	cfg := &config.Config{
		Format: testFormatMarkdown,
	}

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())
	SetCommandContext(cmd, &CommandContext{
		Config: cfg,
		Logger: testLogger,
	})
	cmd.Flags().StringVar(&format, "format", testFormatMarkdown, "")
	cmd.Flags().StringVar(&outputFile, "output", outFile, "")

	err = runAudit(cmd, []string{testdataPath})
	require.NoError(t, err)

	// Verify file was created with content
	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.NotEmpty(t, data, "output file should have content")
}

// TestRunAuditRedMode verifies that runAudit works with red (recon) mode.
// Red mode with markdown format renders through glamour to os.Stdout, so
// we use file output to capture the result.
func TestRunAuditRedMode(t *testing.T) {
	testdataPath := filepath.Join("..", "testdata", "sample.config.1.xml")
	if _, err := os.Stat(testdataPath); os.IsNotExist(err) {
		t.Fatal("required testdata not available — ensure testdata/ is checked out")
	}

	auditSnap := captureAuditFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		auditSnap.restore()
		sharedSnap.restore()
	})

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "red-audit.md")

	auditMode = testAuditModeRed
	format = testFormatMarkdown
	outputFile = outFile
	force = true

	testLogger, err := logging.New(logging.Config{Level: "error"})
	require.NoError(t, err)

	cfg := &config.Config{
		Format: testFormatMarkdown,
	}

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())
	SetCommandContext(cmd, &CommandContext{
		Config: cfg,
		Logger: testLogger,
	})
	cmd.Flags().StringVar(&format, "format", testFormatMarkdown, "")
	cmd.Flags().StringVar(&outputFile, "output", outFile, "")

	err = runAudit(cmd, []string{testdataPath})
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.NotEmpty(t, data, "red mode audit should produce file output")
}

// TestRunAuditMultiFile verifies that runAudit handles multiple input files
// by producing auto-named output files.
func TestRunAuditMultiFile(t *testing.T) {
	relPath1 := filepath.Join("..", "testdata", "sample.config.1.xml")
	relPath2 := filepath.Join("..", "testdata", "sample.config.2.xml")
	if _, err := os.Stat(relPath1); os.IsNotExist(err) {
		t.Fatal("required testdata not available — ensure testdata/ is checked out")
	}
	if _, err := os.Stat(relPath2); os.IsNotExist(err) {
		t.Fatal("required testdata not available — ensure testdata/ is checked out")
	}

	// Convert to absolute paths before changing directories
	absPath1, err := filepath.Abs(relPath1)
	require.NoError(t, err)
	absPath2, err := filepath.Abs(relPath2)
	require.NoError(t, err)

	auditSnap := captureAuditFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		auditSnap.restore()
		sharedSnap.restore()
	})

	auditMode = testAuditModeBlue
	format = testFormatMarkdown
	outputFile = "" // No explicit output — triggers auto-naming
	force = true

	testLogger, err := logging.New(logging.Config{Level: "error"})
	require.NoError(t, err)

	cfg := &config.Config{
		Format: testFormatMarkdown,
	}

	// Use a temp dir as working directory so auto-named files go there
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())
	SetCommandContext(cmd, &CommandContext{
		Config: cfg,
		Logger: testLogger,
	})
	cmd.Flags().StringVar(&format, "format", testFormatMarkdown, "")
	cmd.Flags().StringVar(&outputFile, "output", "", "")

	err = runAudit(cmd, []string{absPath1, absPath2})
	require.NoError(t, err)

	// Verify auto-named output files were created
	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)

	auditFiles := 0
	for _, e := range entries {
		if !e.IsDir() {
			auditFiles++
		}
	}
	assert.Equal(t, 2, auditFiles, "should produce 2 auto-named output files for 2 inputs")
}

// TestGenerateAuditOutput verifies that generateAuditOutput produces
// output without performing any I/O emission.
func TestGenerateAuditOutput(t *testing.T) {
	testdataPath := filepath.Join("..", "testdata", "sample.config.1.xml")
	if _, err := os.Stat(testdataPath); os.IsNotExist(err) {
		t.Fatal("required testdata not available — ensure testdata/ is checked out")
	}

	auditSnap := captureAuditFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		auditSnap.restore()
		sharedSnap.restore()
	})

	auditMode = testAuditModeBlue
	format = testFormatMarkdown

	testLogger, err := logging.New(logging.Config{Level: "error"})
	require.NoError(t, err)

	cfg := &config.Config{
		Format: testFormatMarkdown,
	}

	ctx := context.Background()
	output, err := generateAuditOutput(ctx, testdataPath, testLogger, cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, output, "generateAuditOutput should return report content")
}

// TestGenerateAuditOutputInvalidFile verifies that generateAuditOutput
// returns an error for non-existent files.
func TestGenerateAuditOutputInvalidFile(t *testing.T) {
	auditSnap := captureAuditFlags()
	sharedSnap := captureSharedFlags()
	t.Cleanup(func() {
		auditSnap.restore()
		sharedSnap.restore()
	})

	auditMode = testAuditModeBlue
	format = testFormatMarkdown

	testLogger, err := logging.New(logging.Config{Level: "error"})
	require.NoError(t, err)

	cfg := &config.Config{
		Format: testFormatMarkdown,
	}

	ctx := context.Background()
	_, err = generateAuditOutput(ctx, "/nonexistent/file.xml", testLogger, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}
