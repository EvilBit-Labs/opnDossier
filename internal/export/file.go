// Package export provides functionality to export data to files.
package export

import (
	"context"
	"fmt"
	"os"
)

const (
	// DefaultFilePermissions defines the default file permissions for exported files.
	DefaultFilePermissions = 0o600
)

// Exporter is the interface for exporting OPNsense configurations.
type Exporter interface {
	Export(ctx context.Context, content, path string) error
}

// FileExporter is a file exporter for OPNsense configurations.
type FileExporter struct{}

// NewFileExporter returns a new instance of FileExporter for exporting data to files.
func NewFileExporter() *FileExporter {
	return &FileExporter{}
}

// Export exports an OPNsense configuration to a file.
func (e *FileExporter) Export(ctx context.Context, content, path string) error {
	if err := os.WriteFile(path, []byte(content), DefaultFilePermissions); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
