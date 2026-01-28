package markdown

import "github.com/EvilBit-Labs/opnDossier/internal/converter"

var (
	// ErrUnsupportedFormat is returned when an unsupported output format is requested.
	ErrUnsupportedFormat = converter.ErrUnsupportedFormat

	// ErrNilConfiguration is returned when the input OPNsense configuration is nil.
	ErrNilConfiguration = converter.ErrNilConfiguration
)
