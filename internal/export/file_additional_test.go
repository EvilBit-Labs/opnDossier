package export

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testLinesLF   = "line1\nline2\n"
	testLinesCRLF = "line1\r\nline2\r\n"
)

func TestNewFileExporter(t *testing.T) {
	t.Run("with logger", func(t *testing.T) {
		logger, err := logging.New(logging.Config{})
		require.NoError(t, err)

		exporter := NewFileExporter(logger)
		assert.NotNil(t, exporter)
		assert.Equal(t, logger, exporter.logger)
	})

	t.Run("with nil logger", func(t *testing.T) {
		exporter := NewFileExporter(nil)
		assert.NotNil(t, exporter)
		assert.Nil(t, exporter.logger)
	})
}

func TestError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		expected string
	}{
		{
			name: "error with cause",
			err: &Error{
				Operation: "write_file",
				Path:      "/test/path",
				Message:   "permission denied",
				Cause:     errors.New("access denied"),
			},
			expected: "export write_file failed for /test/path: permission denied (caused by: access denied)",
		},
		{
			name: "error without cause",
			err: &Error{
				Operation: "validate_path",
				Path:      "/test/path",
				Message:   "invalid path",
				Cause:     nil,
			},
			expected: "export validate_path failed for /test/path: invalid path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	originalErr := errors.New("original error")
	err := &Error{
		Operation: "test",
		Path:      "/test",
		Message:   "test message",
		Cause:     originalErr,
	}

	unwrapped := err.Unwrap()
	assert.Equal(t, originalErr, unwrapped)
}

func TestFileExporter_CheckPathTraversal(t *testing.T) {
	exporter := NewFileExporter(nil)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "normal path",
			path:    "test.txt",
			wantErr: false,
		},
		{
			name:    "absolute path",
			path:    "/tmp/test.txt",
			wantErr: false,
		},
		{
			name:    "single parent directory",
			path:    "../test.txt",
			wantErr: false,
		},
		{
			name:    "multiple parent directories",
			path:    "../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "deeply nested traversal",
			path:    "../../../../../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "mixed path with traversal",
			path:    "normal/path/../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "no traversal",
			path:    "normal/path/file.txt",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := exporter.checkPathTraversal(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				var exportErr *Error
				require.ErrorAs(t, err, &exportErr)
				assert.Equal(t, "validate_path", exportErr.Operation)
				assert.Contains(t, exportErr.Message, "malicious traversal")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFileExporter_ResolveAbsolutePath(t *testing.T) {
	exporter := NewFileExporter(nil)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "relative path",
			path:    "test.txt",
			wantErr: false,
		},
		{
			name:    "absolute path",
			path:    filepath.Join(t.TempDir(), "test.txt"),
			wantErr: false,
		},
		{
			name:    "path with dots",
			path:    "./test.txt",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := exporter.resolveAbsolutePath(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, result)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, result)
				assert.True(t, filepath.IsAbs(result))
			}
		})
	}
}

func TestFileExporter_ValidateTargetDirectory(t *testing.T) {
	exporter := NewFileExporter(nil)
	tempDir := t.TempDir()

	tests := []struct {
		name     string
		absPath  string
		origPath string
		wantErr  bool
		setup    func() string
	}{
		{
			name:     "valid directory",
			origPath: "test.txt",
			wantErr:  false,
			setup: func() string {
				return filepath.Join(tempDir, "test.txt")
			},
		},
		{
			name:     "nonexistent directory",
			origPath: "test.txt",
			wantErr:  true,
			setup: func() string {
				return filepath.Join(tempDir, "nonexistent", "test.txt")
			},
		},
		{
			name:     "directory is actually a file",
			origPath: "test.txt",
			wantErr:  true,
			setup: func() string {
				// Create a file where we expect a directory
				filePath := filepath.Join(tempDir, "not-a-dir")
				err := os.WriteFile(filePath, []byte("test"), 0o600)
				require.NoError(t, err)
				return filepath.Join(filePath, "test.txt")
			},
		},
		{
			name:     "current directory",
			absPath:  "./test.txt",
			origPath: "test.txt",
			wantErr:  false,
			setup:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var absPath string
			if tt.setup != nil {
				absPath = tt.setup()
			} else {
				absPath = tt.absPath
			}

			err := exporter.validateTargetDirectory(absPath, tt.origPath)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFileExporter_CheckExistingFilePermissions(t *testing.T) {
	exporter := NewFileExporter(nil)
	tempDir := t.TempDir()

	t.Run("file does not exist", func(t *testing.T) {
		nonExistentPath := filepath.Join(tempDir, "does-not-exist.txt")
		err := exporter.checkExistingFilePermissions(nonExistentPath, "does-not-exist.txt")
		assert.NoError(t, err)
	})

	t.Run("existing writable file", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "writable.txt")
		err := os.WriteFile(filePath, []byte("test"), 0o600)
		require.NoError(t, err)

		err = exporter.checkExistingFilePermissions(filePath, "writable.txt")
		assert.NoError(t, err)
	})

	t.Run("existing directory (not regular file)", func(t *testing.T) {
		dirPath := filepath.Join(tempDir, "testdir")
		err := os.Mkdir(dirPath, 0o700)
		require.NoError(t, err)

		err = exporter.checkExistingFilePermissions(dirPath, "testdir")
		require.Error(t, err)
		var exportErr *Error
		require.ErrorAs(t, err, &exportErr)
		assert.Equal(t, "validate_path", exportErr.Operation)
		assert.Contains(t, exportErr.Message, "not writable")
	})
}

func TestFileExporter_CheckDirectoryWritable(t *testing.T) {
	exporter := NewFileExporter(nil)

	t.Run("writable directory", func(t *testing.T) {
		tempDir := t.TempDir()
		err := exporter.checkDirectoryWritable(tempDir)
		assert.NoError(t, err)
	})

	t.Run("nonexistent directory", func(t *testing.T) {
		nonExistentDir := filepath.Join(t.TempDir(), "nonexistent")
		err := exporter.checkDirectoryWritable(nonExistentDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "directory write test failed")
	})
}

func TestFileExporter_CheckFileWritableAdditional(t *testing.T) {
	exporter := NewFileExporter(nil)
	tempDir := t.TempDir()

	t.Run("writable regular file", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "writable.txt")
		err := os.WriteFile(filePath, []byte("test"), 0o600)
		require.NoError(t, err)

		fileInfo, err := os.Stat(filePath)
		require.NoError(t, err)

		err = exporter.checkFileWritable(filePath, fileInfo)
		assert.NoError(t, err)
	})

	t.Run("directory not regular file", func(t *testing.T) {
		dirPath := filepath.Join(tempDir, "testdir")
		err := os.Mkdir(dirPath, 0o700)
		require.NoError(t, err)

		fileInfo, err := os.Stat(dirPath)
		require.NoError(t, err)

		err = exporter.checkFileWritable(dirPath, fileInfo)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPathNotRegularFile)
	})
}

func TestFileExporter_WriteFileAtomic(t *testing.T) {
	exporter := NewFileExporter(nil)
	tempDir := t.TempDir()

	t.Run("successful write", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "test.txt")
		content := []byte("test content")

		err := exporter.writeFileAtomic(filePath, content)
		require.NoError(t, err)

		// Verify file was created with correct content
		writtenContent, err := os.ReadFile(filePath)
		require.NoError(t, err)
		assert.Equal(t, content, writtenContent)

		// Verify file has correct permissions (on macOS/Linux, umask may affect actual permissions)
		fileInfo, err := os.Stat(filePath)
		require.NoError(t, err)
		actualPerm := fileInfo.Mode() & os.ModePerm
		// File should be readable/writable by owner at minimum
		assert.Equal(
			t,
			os.FileMode(0o600),
			actualPerm&0o600,
			"File should be readable/writable by owner, got %o",
			actualPerm,
		)
	})

	t.Run("empty content", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "empty.txt")
		content := []byte{}

		err := exporter.writeFileAtomic(filePath, content)
		require.ErrorIs(t, err, ErrEmptyContent)

		// File should not exist
		_, err = os.Stat(filePath)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("nonexistent directory", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "nonexistent", "test.txt")
		content := []byte("test content")

		err := exporter.writeFileAtomic(filePath, content)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create temporary file")
	})
}

func TestFileExporter_Export_ContextCancellation(t *testing.T) {
	exporter := NewFileExporter(nil)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	filePath := filepath.Join(t.TempDir(), "test.txt")
	err := exporter.Export(ctx, "test content", filePath)

	require.Error(t, err)
	var exportErr *Error
	require.ErrorAs(t, err, &exportErr)
	assert.Equal(t, "export", exportErr.Operation)
	assert.Contains(t, exportErr.Message, "cancelled by context")
	assert.ErrorIs(t, exportErr.Cause, context.Canceled)
}

func TestFileExporter_Export_WithLogger(t *testing.T) {
	logger, err := logging.New(logging.Config{Level: "debug"})
	require.NoError(t, err)

	exporter := NewFileExporter(logger)
	filePath := filepath.Join(t.TempDir(), "test.txt")

	// Set environment variable to trigger line ending normalization
	t.Setenv("OPNDOSSIER_PLATFORM_LINE_ENDINGS", "1")

	content := "line1\nline2\nline3"
	err = exporter.Export(context.Background(), content, filePath)
	require.NoError(t, err)

	// Verify content was written
	writtenContent, err := os.ReadFile(filePath)
	require.NoError(t, err)

	expectedContent := content
	if runtime.GOOS == windowsOS {
		expectedContent = strings.ReplaceAll(content, "\n", "\r\n")
	}
	assert.Equal(t, expectedContent, string(writtenContent))
}

func TestNormalizeLineEndings_InvalidEnvironmentValue(t *testing.T) {
	logger, err := logging.New(logging.Config{Level: "debug"})
	require.NoError(t, err)

	tests := []struct {
		name     string
		envValue string
		content  string
		expected string
	}{
		{
			name:     "invalid value - true",
			envValue: "true",
			content:  testLinesLF,
			expected: testLinesLF, // Should remain unchanged
		},
		{
			name:     "invalid value - yes",
			envValue: "yes",
			content:  testLinesLF,
			expected: testLinesLF, // Should remain unchanged
		},
		{
			name:     "valid value - 1",
			envValue: "1",
			content:  testLinesLF,
			expected: func() string {
				if runtime.GOOS == windowsOS {
					return testLinesCRLF
				}
				return testLinesLF
			}(),
		},
		{
			name:     "empty value",
			envValue: "",
			content:  testLinesLF,
			expected: testLinesLF, // Should remain unchanged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OPNDOSSIER_PLATFORM_LINE_ENDINGS", tt.envValue)

			result := normalizeLineEndings(logger, tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeLineEndings_WithNilLoggerAdditional(t *testing.T) {
	// Test with invalid environment value and nil logger (should not panic)
	t.Setenv("OPNDOSSIER_PLATFORM_LINE_ENDINGS", "invalid")

	result := normalizeLineEndings(nil, testLinesLF)
	assert.Equal(t, testLinesLF, result) // Should remain unchanged
}

func TestNormalizeLineEndings_MixedLineEndings(t *testing.T) {
	t.Setenv("OPNDOSSIER_PLATFORM_LINE_ENDINGS", "1")

	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:    "CRLF input",
			content: testLinesCRLF,
			expected: func() string {
				if runtime.GOOS == windowsOS {
					return testLinesCRLF
				}
				return testLinesLF
			}(),
		},
		{
			name:    "CR input",
			content: "line1\rline2\r",
			expected: func() string {
				if runtime.GOOS == windowsOS {
					return testLinesCRLF
				}
				return testLinesLF
			}(),
		},
		{
			name:    "mixed line endings",
			content: "line1\r\nline2\nline3\rline4",
			expected: func() string {
				if runtime.GOOS == windowsOS {
					return "line1\r\nline2\r\nline3\r\nline4"
				}
				return "line1\nline2\nline3\nline4"
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeLineEndings(nil, tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFileExporter_ValidateExportPath_EdgeCases(t *testing.T) {
	exporter := NewFileExporter(nil)
	tempDir := t.TempDir()

	t.Run("file in current directory", func(t *testing.T) {
		// Change to temp directory for this test
		t.Chdir(tempDir)

		err := exporter.validateExportPath("test.txt")
		assert.NoError(t, err)
	})

	t.Run("absolute path to existing file", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "existing.txt")
		err := os.WriteFile(filePath, []byte("test"), 0o600)
		require.NoError(t, err)

		err = exporter.validateExportPath(filePath)
		assert.NoError(t, err)
	})
}
