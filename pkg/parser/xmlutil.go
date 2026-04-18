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

// WrapDecodeError annotates an encoding/xml decode error with the element
// path of the failing node so operators can identify the exact field that
// failed to parse. The path is caller-supplied (e.g., "/opnsense/system"
// or "/pfsense") because XML decoding does not expose the full element
// stack once control is inside encoding/xml. Callers that decode
// section-by-section can build deep paths; callers that decode the entire
// document at once can at least supply the root name.
//
// Returns nil when err is nil so it is safe to call unconditionally.
//
// Both the OPNsense and pfSense parsers delegate to this function to avoid
// duplicating error-wrapping logic. Future device parsers registered with
// [Register] should do the same.
func WrapDecodeError(err error, elementPath string) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("field %q: %w", elementPath, err)
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
