package converter

import "errors"

var (
	// ErrUnsupportedFormat is returned when an unsupported output format is requested.
	ErrUnsupportedFormat = errors.New("unsupported format")

	// ErrNilConfiguration is returned when the input OPNsense configuration is nil.
	ErrNilConfiguration = errors.New("configuration cannot be nil")

	// ErrTemplateNotFound is returned when a requested template is not found.
	ErrTemplateNotFound = errors.New("template not found")

	// ErrTemplateExecution is returned when template execution fails.
	ErrTemplateExecution = errors.New("template execution failed")

	// ErrUnsupportedDataType is returned when the data type for markdown generation is unsupported.
	ErrUnsupportedDataType = errors.New("unsupported data type for markdown generation")
)
