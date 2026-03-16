package model

import (
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
)

// DeviceParser is the interface for device-specific parsers.
// Re-exported from pkg/parser for backward compatibility with unlisted consumers.
type DeviceParser = parser.DeviceParser

// ParserFactory detects device type and delegates to the appropriate DeviceParser.
// Re-exported from pkg/parser for backward compatibility with unlisted consumers.
type ParserFactory = parser.ParserFactory

// NewParserFactory returns a new ParserFactory.
// Re-exported from pkg/parser for backward compatibility with unlisted consumers.
func NewParserFactory() *ParserFactory {
	return parser.NewParserFactory()
}
