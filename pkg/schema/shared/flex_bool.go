package shared

import (
	"encoding/json"
	"encoding/xml"
	"fmt"

	"gopkg.in/yaml.v3"
)

// FlexBool is a value-level liberal boolean for XML-encoded configuration
// fields where the source device may emit any of the recognised truthy or
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
type FlexBool bool

// Bool returns the underlying boolean value for convenient comparison at
// call sites that do not want to cast explicitly. Uses a value receiver so
// it can be called on non-addressable values (e.g., `FlexBool(true).Bool()`).
//
//nolint:recvcheck // Bool is intentionally a value receiver for ergonomics; Marshal/Unmarshal must be pointer receivers.
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

// UnmarshalJSON implements [json.Unmarshaler]. Accepts native booleans,
// native integers (0/1), and strings in the [IsValueTrue] vocabulary. Any
// other JSON value — including numeric values outside {0,1}, null, and
// unrecognised strings — unmarshals to false without error, consistent
// with the type-level "unknown → false" contract.
//
// Delegates string decoding to encoding/json so escape sequences (e.g.
// "\u006fn") are decoded before being compared against the truthy vocabulary.
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

// UnmarshalYAML implements the yaml.v3 Unmarshaler interface. Accepts any
// scalar form (bool, int, string) and delegates to [IsValueTrue] for
// interpretation.
func (fb *FlexBool) UnmarshalYAML(node *yaml.Node) error {
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
