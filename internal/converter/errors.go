package converter

import "errors"

var (
	// ErrUnsupportedFormat is returned when an unsupported output format is requested.
	ErrUnsupportedFormat = errors.New("unsupported format")

	// ErrNilConfiguration is returned when the input OPNsense configuration is nil.
	ErrNilConfiguration = errors.New("configuration cannot be nil")

	// ErrNilDevice is returned when the input device configuration is nil.
	ErrNilDevice = errors.New("device configuration is nil")
)
