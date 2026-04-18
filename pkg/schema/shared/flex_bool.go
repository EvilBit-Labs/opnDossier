package shared

import (
	"encoding/json"
	"encoding/xml"
	"fmt"

	"gopkg.in/yaml.v3"
)

// FlexBool is a value-level liberal boolean for XML-encoded configuration
// fields where the source device may emit any of the recognized truthy or
// falsy strings ("1", "on", "yes", "true", etc. — see [IsValueTrue] for the
// full vocabulary).
//
// Use FlexBool on schema fields whose element is always emitted and whose
// content carries the boolean signal. If the element's presence itself is
// the signal (i.e., <tag/> means true and absence means false), use
// BoolFlag instead — BoolFlag and FlexBool both delegate body parsing to
// [IsValueTrue] so they share the same liberal vocabulary.
//
// FlexBool marshals to XML as "1" (true) or "0" (false) for determinism
// in reserialised output. JSON and YAML round-trip as native booleans.
// Unknown values unmarshal to false without error; callers that need to
// flag unknown inputs should pre-validate with [IsValueTrue] and
// [IsValueFalse].
//
// The Marshal/Unmarshal methods require pointer receivers to satisfy the
// encoding interfaces, while the Bool accessor uses a value receiver for
// ergonomics (so `FlexBool(true).Bool()` works on non-addressable
// values). recvcheck is suppressed because the mixed-receiver convention
// is intentional.
//
//nolint:recvcheck // Marshal/Unmarshal require pointer receivers; Bool() uses a value receiver for ergonomics.
type FlexBool bool

// Bool returns the underlying boolean value for convenient comparison at
// call sites that do not want to cast explicitly. Uses a value receiver so
// it can be called on non-addressable values (e.g., `FlexBool(true).Bool()`).
func (fb FlexBool) Bool() bool {
	return bool(fb)
}

// UnmarshalXML implements [xml.Unmarshaler] for FlexBool.
// The element body is decoded as a string and interpreted by [IsValueTrue].
func (fb *FlexBool) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var body string
	if err := d.DecodeElement(&body, &start); err != nil {
		return fmt.Errorf("decode FlexBool body: %w", err)
	}

	*fb = FlexBool(IsValueTrue(body))

	return nil
}

// MarshalXML implements [xml.Marshaler] for FlexBool.
// True marshals as "1", false as "0" — canonical numeric form so downstream
// tooling sees deterministic output.
func (fb *FlexBool) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	value := "0"
	if *fb {
		value = "1"
	}

	return e.EncodeElement(value, start)
}

// UnmarshalJSON implements [json.Unmarshaler]. Accepts:
//   - Native booleans: true → true, false → false.
//   - Native integers: any non-zero integer → true, 0 → false. Note that
//     this intentionally widens beyond the canonical {0,1} — a value of
//     42 is treated as truthy.
//   - Strings: decoded via encoding/json (so escapes are honored) and
//     passed to [IsValueTrue]. Unrecognized strings (e.g., "banana") and
//     null unmarshal to false without error, consistent with the
//     type-level "unknown → false" contract.
//
// Fully malformed JSON (bytes that are neither a bool, number, nor
// string) returns a wrapped error.
func (fb *FlexBool) UnmarshalJSON(data []byte) error {
	// Native bool: true/false.
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*fb = FlexBool(b)

		return nil
	}

	// Native number: 0/1 (and any non-zero integer is truthy).
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		*fb = FlexBool(n != 0)

		return nil
	}

	// Fall back to string — json.Unmarshal decodes escapes before
	// IsValueTrue inspects the vocabulary.
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("decode FlexBool: %w", err)
	}

	*fb = FlexBool(IsValueTrue(s))

	return nil
}

// MarshalJSON implements [json.Marshaler], emitting a native JSON boolean.
func (fb *FlexBool) MarshalJSON() ([]byte, error) {
	if *fb {
		return []byte("true"), nil
	}

	return []byte("false"), nil
}

// UnmarshalYAML implements the yaml.v3 Unmarshaler interface. Matches
// UnmarshalJSON's behavior: native YAML booleans (`true`/`false`), integers
// (0 → false, non-zero → true), and strings in the [IsValueTrue]
// vocabulary all parse cleanly. Unrecognized scalars and null unmarshal
// to false without error, consistent with the "unknown → false" contract.
func (fb *FlexBool) UnmarshalYAML(node *yaml.Node) error {
	// Native bool scalars: !!bool with value "true"/"false".
	if node.Tag == "!!bool" {
		var b bool
		if err := node.Decode(&b); err == nil {
			*fb = FlexBool(b)

			return nil
		}
	}

	// Native integer scalars: any non-zero integer → true.
	if node.Tag == "!!int" {
		var n int
		if err := node.Decode(&n); err == nil {
			*fb = FlexBool(n != 0)

			return nil
		}
	}

	// Fall back to string vocabulary (covers quoted strings and unknown
	// scalars — the "unknown → false" contract).
	*fb = FlexBool(IsValueTrue(node.Value))

	return nil
}

// MarshalYAML implements the yaml.v3 Marshaler interface, emitting a
// native YAML boolean.
func (fb *FlexBool) MarshalYAML() (any, error) {
	return bool(*fb), nil
}

// Compile-time interface compliance checks.
var (
	_ xml.Marshaler    = (*FlexBool)(nil)
	_ xml.Unmarshaler  = (*FlexBool)(nil)
	_ json.Marshaler   = (*FlexBool)(nil)
	_ json.Unmarshaler = (*FlexBool)(nil)
	_ yaml.Marshaler   = (*FlexBool)(nil)
	_ yaml.Unmarshaler = (*FlexBool)(nil)
)
