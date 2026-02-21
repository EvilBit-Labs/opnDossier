package converter

import "errors"

var (
	// ErrUnsupportedFormat is returned when an unsupported output format is requested.
	ErrUnsupportedFormat = errors.New("unsupported format")

	// ErrNilDevice is returned when the input device configuration is nil.
	ErrNilDevice = errors.New("device configuration is nil")
)
