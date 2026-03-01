// Package export provides functionality to export data to files.
package export

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/logging"
)

const (
	// DefaultFilePermissions defines the default file permissions for exported files.
	DefaultFilePermissions = 0o600

	// windowsOS is the GOOS value for Windows.
	windowsOS = "windows"
)

// normalizeLineEndings converts line endings to the platform-appropriate format
// for file exports, but only if explicitly enabled via the OPNDOSSIER_PLATFORM_LINE_ENDINGS
// environment variable.
//
// By default, exports use LF line endings for deterministic cross-platform builds.
// To enable platform-specific line endings, set OPNDOSSIER_PLATFORM_LINE_ENDINGS=1
//
// When enabled:
//   - Windows: \r\n (CRLF)
//   - Unix-like: \n (LF)
//
// Only the value "1" enables this feature. Other values ("true", "yes", etc.) are ignored.
func normalizeLineEndings(logger *logging.Logger, content string) string {
	envValue := os.Getenv("OPNDOSSIER_PLATFORM_LINE_ENDINGS")

	// Warn if environment variable is set to an invalid value
	if envValue != "" && envValue != "1" {
		if logger != nil {
			logger.Warn("Invalid value for OPNDOSSIER_PLATFORM_LINE_ENDINGS environment variable",
				"value", envValue,
				"expected", "1",
				"note", "line endings will remain LF-normalized")
		}
	}

	// Only normalize if explicitly enabled
	if envValue != "1" {
		return content
	}

	// First, normalize all line endings to \n (LF)
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	// When platform normalization is enabled and on Windows, convert to CRLF
	if runtime.GOOS == windowsOS {
		content = strings.ReplaceAll(content, "\n", "\r\n")
	}

	return content
}

// Define static errors for better error handling.
var (
	// ErrPathNotRegularFile is returned when the target path exists but is not a regular file.
	ErrPathNotRegularFile = errors.New("path exists but is not a regular file")
	// ErrEmptyContent is returned when attempting to export empty content.
	ErrEmptyContent = errors.New("cannot export empty content")
	// ErrOperationCancelled is returned when an export operation is cancelled by context.
	ErrOperationCancelled = errors.New("operation cancelled by context")
)

// Error represents an error that occurred during file export operations.
type Error struct {
	Operation string // The operation that failed (e.g., "validate_path", "create_directory", "write_file")
	Path      string // The file path involved in the error
	Message   string // Human-readable error message
	Cause     error  // The underlying error that caused this export error
}

// Error implements the error interface for Error.
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("export %s failed for %s: %s (caused by: %v)", e.Operation, e.Path, e.Message, e.Cause)
	}

	return fmt.Sprintf("export %s failed for %s: %s", e.Operation, e.Path, e.Message)
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error {
	return e.Cause
}

// Exporter is the interface for exporting OPNsense configurations.
type Exporter interface {
	Export(ctx context.Context, content, path string) error
}

// FileExporter is a file exporter for OPNsense configurations.
type FileExporter struct {
	logger *logging.Logger
}

// NewFileExporter creates and returns a new FileExporter for writing data to files.
// If logger is nil, operations will continue without logging (graceful degradation).
func NewFileExporter(logger *logging.Logger) *FileExporter {
	return &FileExporter{
		logger: logger,
	}
}

// validateExportPath performs comprehensive validation of the export path.
// It checks for path traversal attacks, validates directory existence and permissions,
// and ensures the path is safe for file operations.
func (e *FileExporter) validateExportPath(path string) error {
	// Check for path traversal attacks
	if err := e.checkPathTraversal(path); err != nil {
		return err
	}

	// Get clean absolute path
	absPath, err := e.resolveAbsolutePath(path)
	if err != nil {
		return err
	}

	// Validate target directory
	if err := e.validateTargetDirectory(absPath, path); err != nil {
		return err
	}

	// Check existing file permissions
	if err := e.checkExistingFilePermissions(absPath, path); err != nil {
		return err
	}

	return nil
}

// checkPathTraversal checks for potentially malicious path traversal patterns.
func (e *FileExporter) checkPathTraversal(path string) error {
	// Check for path traversal attempts BEFORE cleaning the path
	// This catches attempts like "../../../etc/passwd" or "test/../../../etc/passwd"
	if strings.Contains(path, "..") {
		// Check if the path contains suspicious traversal patterns
		parts := strings.Split(path, string(filepath.Separator))
		dotDotCount := 0

		for _, part := range parts {
			if part == ".." {
				dotDotCount++
			}
		}
		// If we have multiple ".." segments, it's likely a traversal attempt
		if dotDotCount > 1 {
			return &Error{
				Operation: "validate_path",
				Path:      path,
				Message:   "path contains potentially malicious traversal sequences",
			}
		}
	}
	return nil
}

// resolveAbsolutePath normalizes and resolves the path to an absolute path.
func (e *FileExporter) resolveAbsolutePath(path string) (string, error) {
	// Normalize the path to handle any path separators and resolve relative paths
	cleanPath := filepath.Clean(path)

	// Get absolute path for further validation
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", &Error{
			Operation: "validate_path",
			Path:      path,
			Message:   "failed to resolve absolute path",
			Cause:     err,
		}
	}
	return absPath, nil
}

// validateTargetDirectory validates the target directory exists and is writable.
func (e *FileExporter) validateTargetDirectory(absPath, originalPath string) error {
	// Check if the target directory exists and is writable
	dir := filepath.Dir(absPath)
	if dir != "." && dir != "" {
		dirInfo, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				return &Error{
					Operation: "validate_path",
					Path:      originalPath,
					Message:   "target directory does not exist: " + dir,
					Cause:     err,
				}
			}

			return &Error{
				Operation: "validate_path",
				Path:      originalPath,
				Message:   "failed to check target directory",
				Cause:     err,
			}
		}

		// Ensure it's actually a directory
		if !dirInfo.IsDir() {
			return &Error{
				Operation: "validate_path",
				Path:      originalPath,
				Message:   "target path is not a directory: " + dir,
			}
		}

		// Check if directory is writable
		if err := e.checkDirectoryWritable(dir); err != nil {
			return &Error{
				Operation: "validate_path",
				Path:      originalPath,
				Message:   "target directory is not writable",
				Cause:     err,
			}
		}
	}
	return nil
}

// checkExistingFilePermissions checks if an existing file at the path is writable.
func (e *FileExporter) checkExistingFilePermissions(absPath, originalPath string) error {
	// Check if file already exists and is writable
	if fileInfo, err := os.Stat(absPath); err == nil {
		// File exists, check if it's writable
		if err := e.checkFileWritable(absPath, fileInfo); err != nil {
			return &Error{
				Operation: "validate_path",
				Path:      originalPath,
				Message:   "existing file is not writable",
				Cause:     err,
			}
		}
	} else if !os.IsNotExist(err) {
		// Some other error occurred while checking file existence
		return &Error{
			Operation: "validate_path",
			Path:      originalPath,
			Message:   "failed to check file existence",
			Cause:     err,
		}
	}
	return nil
}

// checkDirectoryWritable checks if a directory is writable by attempting to create a temporary file.
func (e *FileExporter) checkDirectoryWritable(dir string) error {
	// Try to create a temporary file in the directory to test write permissions
	tempFile, err := os.CreateTemp(dir, ".opndossier_write_test_*")
	if err != nil {
		return fmt.Errorf("directory write test failed: %w", err)
	}

	// Clean up the temporary file
	tempPath := tempFile.Name()
	if closeErr := tempFile.Close(); closeErr != nil {
		return fmt.Errorf("failed to close test file: %w", closeErr)
	}

	//nolint:gosec // tempPath is generated by os.CreateTemp in checkDirectoryWritable and not user-controlled.
	if removeErr := os.Remove(tempPath); removeErr != nil && e.logger != nil {
		e.logger.Warn("failed to remove write-test file", "path", tempPath, "error", removeErr)
	}

	return nil
}

// checkFileWritable checks if an existing file is writable.
func (e *FileExporter) checkFileWritable(path string, fileInfo os.FileInfo) error {
	// Check if file is a regular file
	if !fileInfo.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrPathNotRegularFile, path)
	}

	// Try to open the file for writing to test write permissions
	// Path has been extensively validated for security in validateExportPath
	file, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304
	if err != nil {
		return fmt.Errorf("file write test failed: %w", err)
	}

	if closeErr := file.Close(); closeErr != nil {
		return fmt.Errorf("failed to close test file: %w", closeErr)
	}

	return nil
}

// Export exports an OPNsense configuration to a file with comprehensive validation and error handling.
func (e *FileExporter) Export(ctx context.Context, content, path string) error {
	// Check if context is cancelled
	if ctx != nil {
		select {
		case <-ctx.Done():
			return &Error{
				Operation: "export",
				Path:      path,
				Message:   "operation cancelled by context",
				Cause:     ctx.Err(),
			}
		default:
		}
	}

	// Validate the export path
	if err := e.validateExportPath(path); err != nil {
		return err
	}

	// Ensure the content is not empty
	if content == "" {
		return &Error{
			Operation: "export",
			Path:      path,
			Message:   "cannot export empty content",
		}
	}

	// Normalize line endings for the target platform before writing
	normalizedContent := normalizeLineEndings(e.logger, content)

	// Write the file with atomic operation for better safety
	if err := e.writeFileAtomic(path, []byte(normalizedContent)); err != nil {
		return &Error{
			Operation: "write_file",
			Path:      path,
			Message:   "failed to write file content",
			Cause:     err,
		}
	}

	return nil
}

// writeFileAtomic writes content to a file using an atomic operation.
// It creates a temporary file first, then renames it to the target location.
func (e *FileExporter) writeFileAtomic(path string, content []byte) error {
	// Check for empty content
	if len(content) == 0 {
		return ErrEmptyContent
	}

	// Create a temporary file in the same directory
	dir := filepath.Dir(path)

	tempFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp_*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}

	tempPath := tempFile.Name()

	// Ensure cleanup on error
	defer func() {
		if tempFile != nil {
			if closeErr := tempFile.Close(); closeErr != nil {
				// Log cleanup failure but don't fail the overall operation
				if e.logger != nil {
					e.logger.Warn("Failed to close temporary file during cleanup",
						"path", tempPath,
						"error", closeErr)
				}
			}
		}
		// Only remove temp file if we haven't successfully renamed it
		if _, statErr := os.Stat(tempPath); statErr == nil {
			if removeErr := os.Remove(tempPath); removeErr != nil {
				// Log cleanup failure but don't fail the overall operation
				if e.logger != nil {
					e.logger.Warn("Failed to remove temporary file during cleanup",
						"path", tempPath,
						"error", removeErr)
				}
			}
		}
	}()

	// Write content to temporary file
	if _, err := tempFile.Write(content); err != nil {
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}

	// Ensure content is flushed to disk
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temporary file: %w", err)
	}

	// Close the temporary file before renaming
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	tempFile = nil // Prevent cleanup in defer

	// Set proper permissions on the temporary file
	//nolint:gosec // tempPath is a process-created temp file in the target directory, validated before use.
	if err := os.Chmod(tempPath, DefaultFilePermissions); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	// Atomically rename temporary file to target location
	//nolint:gosec // path is validated by validateExportPath and tempPath is created locally by os.CreateTemp.
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("failed to rename temporary file to target: %w", err)
	}

	return nil
}
