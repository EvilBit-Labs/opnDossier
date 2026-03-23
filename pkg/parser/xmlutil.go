// Package parser provides shared XML utilities for device-specific parsers.
package parser

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

// NewSecureXMLDecoder returns an *xml.Decoder configured with security hardening:
//   - Input size limited to maxSize bytes (prevents XML bomb attacks)
//   - Entity expansion disabled (prevents XXE attacks)
//   - Charset reader for UTF-8, US-ASCII, ISO-8859-1, and Windows-1252
//
// Both the OPNsense and pfSense parsers delegate to this function to avoid
// duplicating security hardening logic.
func NewSecureXMLDecoder(r io.Reader, maxSize int64) *xml.Decoder {
	dec := xml.NewDecoder(io.LimitReader(r, maxSize))
	dec.Entity = map[string]string{}
	dec.CharsetReader = CharsetReader

	return dec
}

// CharsetReader creates a reader for the specified XML charset declaration.
// Supported encodings: UTF-8, US-ASCII, ISO-8859-1 (Latin1), and Windows-1252.
// Only charsets whose ASCII subset matches UTF-8 are accepted, which is
// sufficient because XML element names use only ASCII-range characters.
func CharsetReader(charset string, input io.Reader) (io.Reader, error) {
	normalized := strings.ToLower(strings.TrimSpace(charset))
	normalized = strings.ReplaceAll(normalized, "_", "-")
	normalized = strings.TrimSuffix(normalized, ":1987")

	switch normalized {
	case "us-ascii", "ascii":
		return input, nil
	case "utf-8", "utf8":
		return input, nil
	case "iso-8859-1", "iso8859-1", "latin1", "latin-1":
		return transform.NewReader(input, charmap.ISO8859_1.NewDecoder()), nil
	case "windows-1252", "windows1252", "cp1252":
		return transform.NewReader(input, charmap.Windows1252.NewDecoder()), nil
	default:
		return nil, fmt.Errorf("unsupported charset: %s", charset)
	}
}
