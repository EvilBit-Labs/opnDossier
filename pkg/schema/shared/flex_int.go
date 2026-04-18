package shared

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// FlexInt is a liberal integer for XML-encoded configuration fields that are
// semantically integers but may receive truthy/falsy strings ("on", "off",
// "yes", "no") in addition to numeric values. Truthy strings coerce to 1,
// falsy strings to 0, clean numerics pass through unchanged. Unknown strings
// return a wrapped error so callers can surface a meaningful message.
//
// Use FlexInt on fields that must retain int semantics (for example, a field
// that sometimes carries a count and sometimes a boolean toggle). For fields
// that are purely boolean, prefer [FlexBool] or BoolFlag for clearer
// downstream consumer semantics.
//
// FlexInt marshals as canonical decimal integer. JSON and YAML round-trip as
// native integers.
//
// Marshal/Unmarshal methods require pointer receivers to satisfy the
// encoding interfaces, while the Int accessor uses a value receiver for
// ergonomics (so `FlexInt(42).Int()` works on non-addressable values).
// recvcheck is suppressed because the mixed-receiver convention is
// intentional.
//
//nolint:recvcheck // Marshal/Unmarshal require pointer receivers; Int() uses a value receiver for ergonomics.
type FlexInt int

// Int returns the underlying int value for convenience at call sites.
// Uses a value receiver so it can be called on non-addressable values
// (e.g., `FlexInt(42).Int()`).
func (fi FlexInt) Int() int {
	return int(fi)
}

// UnmarshalXML implements [xml.Unmarshaler] for FlexInt.
func (fi *FlexInt) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var body string
	if err := d.DecodeElement(&body, &start); err != nil {
		return fmt.Errorf("decode FlexInt body: %w", err)
	}

	return fi.parse(body)
}

// MarshalXML implements [xml.Marshaler] for FlexInt.
func (fi *FlexInt) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(strconv.Itoa(int(*fi)), start)
}

// UnmarshalJSON implements [json.Unmarshaler]. Accepts raw integers, bool
// literals, and string forms recognized by [IsValueTrue] / [IsValueFalse].
func (fi *FlexInt) UnmarshalJSON(data []byte) error {
	// Try native int first.
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		*fi = FlexInt(n)
		return nil
	}

	// Native bool.
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		if b {
			*fi = 1
		} else {
			*fi = 0
		}
		return nil
	}

	// Fall back to string form.
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("decode FlexInt: %w", err)
	}

	return fi.parse(s)
}

// MarshalJSON implements [json.Marshaler], emitting a native JSON integer.
func (fi *FlexInt) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Itoa(int(*fi))), nil
}

// UnmarshalYAML implements the yaml.v3 Unmarshaler interface. Matches
// FlexBool.UnmarshalYAML's branching: native !!int scalars are decoded by
// yaml.v3 (so non-decimal forms like 0x10 and underscored 1_000 work
// correctly), native !!bool scalars coerce to 0/1, and string-tagged
// scalars fall through to parse(). This mirrors the FlexBool contract so
// callers see consistent behavior across both types.
func (fi *FlexInt) UnmarshalYAML(node *yaml.Node) error {
	switch node.Tag {
	case "!!int":
		var n int
		if err := node.Decode(&n); err == nil {
			*fi = FlexInt(n)

			return nil
		}
	case "!!bool":
		var b bool
		if err := node.Decode(&b); err == nil {
			if b {
				*fi = 1
			} else {
				*fi = 0
			}

			return nil
		}
	}

	// Fall back to string vocabulary (covers quoted strings, tagged
	// strings, and anything else that didn't decode cleanly above).
	return fi.parse(node.Value)
}

// MarshalYAML implements the yaml.v3 Marshaler interface, emitting a native
// YAML integer.
func (fi *FlexInt) MarshalYAML() (any, error) {
	return int(*fi), nil
}

// parse interprets s as either a decimal integer or a liberal boolean
// string. Numeric inputs pass through; "on"/"yes"/"true"/etc. → 1;
// "off"/"no"/"false"/"" → 0. Unknown strings return a wrapped error.
func (fi *FlexInt) parse(s string) error {
	trimmed := strings.TrimSpace(s)

	// Prefer numeric interpretation — a value of "1" should be 1 even
	// though IsValueTrue would also accept it.
	if n, err := strconv.Atoi(trimmed); err == nil {
		*fi = FlexInt(n)
		return nil
	}

	if IsValueTrue(trimmed) {
		*fi = 1
		return nil
	}

	if IsValueFalse(trimmed) {
		*fi = 0
		return nil
	}

	return fmt.Errorf("invalid FlexInt value %q: not numeric and not a recognized boolean", s)
}

// Compile-time interface compliance checks.
var (
	_ xml.Marshaler    = (*FlexInt)(nil)
	_ xml.Unmarshaler  = (*FlexInt)(nil)
	_ json.Marshaler   = (*FlexInt)(nil)
	_ json.Unmarshaler = (*FlexInt)(nil)
	_ yaml.Marshaler   = (*FlexInt)(nil)
	_ yaml.Unmarshaler = (*FlexInt)(nil)
)
