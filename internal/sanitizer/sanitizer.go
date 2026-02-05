// Package sanitizer provides functionality to redact sensitive information
// from OPNsense configuration files.
package sanitizer

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Sanitizer orchestrates the redaction of sensitive data from OPNsense configuration.
type Sanitizer struct {
	engine *RuleEngine
	mode   Mode
	stats  *Stats
}

// Stats tracks sanitization statistics.
type Stats struct {
	TotalFields      int
	RedactedFields   int
	SkippedFields    int
	RedactionsByType map[string]int
}

// NewSanitizer creates a new Sanitizer with the specified mode.
func NewSanitizer(mode Mode) *Sanitizer {
	return &Sanitizer{
		engine: NewRuleEngine(mode),
		mode:   mode,
		stats: &Stats{
			RedactionsByType: make(map[string]int),
		},
	}
}

// GetStats returns the current sanitization statistics.
func (s *Sanitizer) GetStats() *Stats {
	return s.stats
}

// GetMapper returns the mapper for generating mapping reports.
func (s *Sanitizer) GetMapper() *Mapper {
	return s.engine.GetMapper()
}

// SanitizeXML reads XML from the reader, sanitizes it, and writes to the writer.
// This processes the XML as a stream, maintaining the original structure.
func (s *Sanitizer) SanitizeXML(r io.Reader, w io.Writer) error {
	// Read entire input
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	// Parse and sanitize
	sanitized, err := s.sanitizeXMLContent(data)
	if err != nil {
		return fmt.Errorf("sanitizing content: %w", err)
	}

	// Write output
	_, err = w.Write(sanitized)
	if err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	return nil
}

// sanitizeXMLContent processes raw XML bytes and returns sanitized XML.
func (s *Sanitizer) sanitizeXMLContent(data []byte) ([]byte, error) {
	// Use a token-based approach to preserve XML structure
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	decoder.Strict = false

	var output strings.Builder
	var elementStack []string

	// Write XML declaration if present
	if strings.HasPrefix(strings.TrimSpace(string(data)), "<?xml") {
		idx := bytes.Index(data, []byte("?>"))
		if idx > 0 {
			output.Write(data[:idx+2])
			output.WriteString("\n")
		}
	}

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing xml: %w", err)
		}

		switch t := token.(type) {
		case xml.StartElement:
			elementStack = append(elementStack, t.Name.Local)
			output.WriteString("<")
			output.WriteString(t.Name.Local)

			// Process attributes
			for _, attr := range t.Attr {
				s.stats.TotalFields++
				sanitizedValue := s.sanitizeValue(t.Name.Local+"."+attr.Name.Local, attr.Value)
				output.WriteString(" ")
				output.WriteString(attr.Name.Local)
				output.WriteString("=\"")
				output.WriteString(escapeXMLAttr(sanitizedValue))
				output.WriteString("\"")
			}
			output.WriteString(">")

		case xml.EndElement:
			if len(elementStack) > 0 {
				elementStack = elementStack[:len(elementStack)-1]
			}
			output.WriteString("</")
			output.WriteString(t.Name.Local)
			output.WriteString(">")

		case xml.CharData:
			content := strings.TrimSpace(string(t))
			if content != "" {
				s.stats.TotalFields++
				currentElement := ""
				if len(elementStack) > 0 {
					currentElement = elementStack[len(elementStack)-1]
				}
				// Build the full path for context
				fullPath := strings.Join(elementStack, ".")
				sanitizedContent := s.sanitizeValue(fullPath, content)
				// Use the element name for additional field-based detection
				if sanitizedContent == content {
					sanitizedContent = s.sanitizeValue(currentElement, content)
				}
				output.WriteString(escapeXMLText(sanitizedContent))
			} else if len(t) > 0 {
				// Preserve whitespace
				output.Write(t)
			}

		case xml.Comment:
			output.WriteString("<!--")
			output.Write(t)
			output.WriteString("-->")

		case xml.ProcInst:
			// Skip processing instructions (already handled XML declaration)
			if t.Target != "xml" {
				output.WriteString("<?")
				output.WriteString(t.Target)
				output.WriteString(" ")
				output.Write(t.Inst)
				output.WriteString("?>")
			}

		case xml.Directive:
			output.WriteString("<!")
			output.Write(t)
			output.WriteString(">")
		}
	}

	return []byte(output.String()), nil
}

// sanitizeValue applies redaction rules to a value based on field name context.
func (s *Sanitizer) sanitizeValue(fieldName, value string) string {
	if value == "" {
		return value
	}

	should, rule := s.engine.ShouldRedactValue(fieldName, value)
	if !should {
		s.stats.SkippedFields++
		return value
	}

	s.stats.RedactedFields++
	if rule != nil {
		s.stats.RedactionsByType[rule.Name]++
	}

	return s.engine.Redact(fieldName, value)
}

// SanitizeStruct uses reflection to sanitize a struct in place.
// This is useful for sanitizing parsed model structs before re-encoding.
func (s *Sanitizer) SanitizeStruct(v any) error {
	return s.sanitizeReflect(reflect.ValueOf(v), "")
}

// sanitizeReflect recursively sanitizes a reflected value.
func (s *Sanitizer) sanitizeReflect(v reflect.Value, path string) error {
	// Handle pointers
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		return s.sanitizeReflect(v.Elem(), path)
	}

	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		for i := range v.NumField() {
			field := v.Field(i)
			fieldType := t.Field(i)

			// Skip unexported fields
			if !field.CanSet() {
				continue
			}

			// Skip XMLName
			if fieldType.Name == "XMLName" {
				continue
			}

			// Build path
			fieldPath := fieldType.Name
			if path != "" {
				fieldPath = path + "." + fieldType.Name
			}

			// Get xml tag for field name context
			xmlTag := fieldType.Tag.Get("xml")
			if xmlTag != "" && xmlTag != "-" {
				parts := strings.Split(xmlTag, ",")
				if parts[0] != "" {
					fieldPath = parts[0]
				}
			}

			if err := s.sanitizeReflect(field, fieldPath); err != nil {
				return err
			}
		}

	case reflect.Slice:
		for i := range v.Len() {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			if err := s.sanitizeReflect(v.Index(i), itemPath); err != nil {
				return err
			}
		}

	case reflect.Map:
		for _, key := range v.MapKeys() {
			mapValue := v.MapIndex(key)
			if mapValue.Kind() == reflect.String && mapValue.CanInterface() {
				keyStr := fmt.Sprintf("%v", key.Interface())
				s.stats.TotalFields++
				original := mapValue.String()
				sanitized := s.sanitizeValue(keyStr, original)
				if sanitized != original {
					// For maps, we need to set the new value
					v.SetMapIndex(key, reflect.ValueOf(sanitized))
				}
			}
			// Note: Complex types (struct/ptr) in maps cannot be modified in place.
			// This is a Go limitation - map values are not addressable.
		}

	case reflect.String:
		if v.CanSet() {
			s.stats.TotalFields++
			original := v.String()
			sanitized := s.sanitizeValue(path, original)
			if sanitized != original {
				v.SetString(sanitized)
			}
		}
	}

	return nil
}

// escapeXMLText escapes special characters for XML text content.
func escapeXMLText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '&':
			b.WriteString("&amp;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// escapeXMLAttr escapes special characters for XML attribute values.
func escapeXMLAttr(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '&':
			b.WriteString("&amp;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
