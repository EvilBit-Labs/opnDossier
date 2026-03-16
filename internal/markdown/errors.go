package markdown

import "github.com/EvilBit-Labs/opnDossier/internal/converter"

// Sentinel errors re-exported from the converter package for public API consumers.
var (
	// ErrUnsupportedFormat is returned when an unsupported output format is requested.
	ErrUnsupportedFormat = converter.ErrUnsupportedFormat

	// ErrNilDevice is returned when the input device configuration is nil.
	ErrNilDevice = converter.ErrNilDevice
)
