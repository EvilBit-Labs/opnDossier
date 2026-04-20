// Package sanitizer provides functionality to redact sensitive information
// from OPNsense configuration files.
package sanitizer

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"reflect"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/pool"
)

// Sanitizer orchestrates the redaction of sensitive data from OPNsense configuration.
type Sanitizer struct {
	engine *RuleEngine
	mode   Mode
	stats  *Stats
	// logger is optional. When nil, reflection-path warnings (e.g. struct-valued
	// maps encountered by SanitizeStruct) are silently dropped. Callers that
	// care about observability should inject a logger via SetLogger.
	logger *logging.Logger
}

// Stats tracks sanitization statistics.
type Stats struct {
	TotalFields      int
	RedactedFields   int
	SkippedFields    int
	RedactionsByType map[string]int
}

// NewSanitizer creates a Sanitizer configured for the given Mode, initializing its rule engine and an empty statistics map for tracking redactions.
// The returned *Sanitizer is ready to perform XML and struct sanitization and to collect sanitization metrics.
func NewSanitizer(mode Mode) *Sanitizer {
	return &Sanitizer{
		engine: NewRuleEngine(mode),
		mode:   mode,
		stats: &Stats{
			RedactionsByType: make(map[string]int),
		},
	}
}

// GetStats returns a copy of the current sanitization statistics.
// The copy ensures callers cannot observe or mutate internal state.
func (s *Sanitizer) GetStats() Stats {
	// Return a copy to prevent data races and external mutation
	redactionsCopy := make(map[string]int, len(s.stats.RedactionsByType))
	maps.Copy(redactionsCopy, s.stats.RedactionsByType)
	return Stats{
		TotalFields:      s.stats.TotalFields,
		RedactedFields:   s.stats.RedactedFields,
		SkippedFields:    s.stats.SkippedFields,
		RedactionsByType: redactionsCopy,
	}
}

// GetMapper returns the mapper for generating mapping reports.
func (s *Sanitizer) GetMapper() *Mapper {
	return s.engine.GetMapper()
}

// SetLogger attaches a structured logger used for reflection-path diagnostics.
// Passing nil is valid and silences diagnostics. The logger is only consulted
// from SanitizeStruct today — the XML path uses the package-level log fallback
// already.
func (s *Sanitizer) SetLogger(logger *logging.Logger) {
	s.logger = logger
}

// maxSanitizeInputSize is the maximum allowed size in bytes for XML input
// to the sanitizer, preventing denial-of-service via oversized payloads.
const maxSanitizeInputSize = 100 * 1024 * 1024 // 100 MB

// SanitizeXML reads XML from the reader, sanitizes it, and writes to the writer.
// This processes the XML as a stream, maintaining the original structure.
// Input is limited to maxSanitizeInputSize bytes to prevent resource exhaustion.
//
// NOTE: SanitizeXML buffers the full input up to maxSanitizeInputSize+1
// via io.ReadAll before streaming through xml.NewDecoder. This is
// intentional: the size check (LimitReader + length comparison) is
// simpler when the full payload is in memory, and 2-10MB peak residency
// is trivial on real hardware. The streaming path (xml.NewDecoder(r))
// would save the buffer but complicates the maxSanitizeInputSize
// rejection gate. If we ever need to sanitize inputs larger than
// maxSanitizeInputSize, revisit — until then, keep as-is.
// See docs/solutions/ for benchmark context when #187 lands.
// See also GOTCHAS.md §14.5.
func (s *Sanitizer) SanitizeXML(r io.Reader, w io.Writer) error {
	// Read entire input, bounded by size limit to prevent resource exhaustion.
	// Buffering is intentional — see the function-level NOTE above.
	data, err := io.ReadAll(io.LimitReader(r, maxSanitizeInputSize+1))
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}
	if int64(len(data)) > maxSanitizeInputSize {
		return fmt.Errorf("input exceeds maximum size of %d bytes", maxSanitizeInputSize)
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
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	// Prevent XXE attacks by disabling entity expansion
	decoder.Entity = map[string]string{}

	var output strings.Builder
	output.Grow(len(data))
	// pathStack tracks element names at each depth. The cumulative dotted
	// path is materialized via strings.Join only at the CharData leaf where
	// ShouldRedactValue is consulted — most tokens (empty/whitespace CharData
	// and all Start/End transitions) skip the join entirely. This avoids
	// O(depth) string allocation per StartElement. See issue #148.
	var pathStack []string

	// Write XML declaration if present
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("<?xml")) {
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
			pathStack = append(pathStack, t.Name.Local)
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
			if len(pathStack) > 0 {
				pathStack = pathStack[:len(pathStack)-1]
			}
			output.WriteString("</")
			output.WriteString(t.Name.Local)
			output.WriteString(">")

		case xml.CharData:
			content := strings.TrimSpace(string(t))
			switch {
			case content != "":
				output.WriteString(escapeXMLText(s.sanitizeCharData(content, pathStack)))
			case len(t) > 0:
				// Preserve whitespace
				output.Write(t)
			}

		case xml.Comment:
			// Sanitize comment content - comments can contain sensitive data
			commentContent := string(t)
			sanitizedComment := s.sanitizeCommentContent(commentContent)
			output.WriteString("<!--")
			output.WriteString(sanitizedComment)
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
			// Strip DTD directives to prevent XXE and entity injection.
			// Replace with an XML comment indicating the directive was removed.
			output.WriteString("<!-- DTD directive stripped -->")
		}
	}

	return []byte(output.String()), nil
}

// sanitizeCharData applies redaction to a non-empty CharData leaf. The
// extracted helper keeps the main token-stream loop flat; stats and
// rule-lookup sequencing are documented inline below.
func (s *Sanitizer) sanitizeCharData(content string, pathStack []string) string {
	s.stats.TotalFields++

	currentElement := ""
	if len(pathStack) > 0 {
		currentElement = pathStack[len(pathStack)-1]
	}
	// Materialize the full dotted path only now, at the leaf where a rule
	// lookup is about to happen. Empty/whitespace CharData tokens are
	// filtered by the caller and never reach this join.
	fullPath := strings.Join(pathStack, ".")

	// Try full path first, then bare element name.
	should, rule := s.engine.ShouldRedactValue(fullPath, content)
	if !should {
		should, rule = s.engine.ShouldRedactValue(currentElement, content)
	}

	if !should {
		s.stats.SkippedFields++
		return content
	}

	// Apply the same rule that ShouldRedactValue matched to avoid a
	// redundant lookup that could attribute the redaction to a different
	// rule in statistics.
	redacted := s.engine.RedactWithRule(rule, fullPath, content)
	// Only count as redacted if the value actually changed; guarded
	// Redactors (e.g., ip_address_field) may return the original value
	// when the guard rejects it.
	if redacted == content {
		s.stats.SkippedFields++
		return redacted
	}
	s.stats.RedactedFields++
	if rule.Name != "" {
		s.stats.RedactionsByType[rule.Name]++
	}
	return redacted
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

	redacted := s.engine.RedactWithRule(rule, fieldName, value)
	if redacted != value {
		s.stats.RedactedFields++
		if rule.Name != "" {
			s.stats.RedactionsByType[rule.Name]++
		}
	} else {
		s.stats.SkippedFields++
	}

	return redacted
}

// sanitizeCommentContent applies redaction to XML comment content.
// Comments can contain sensitive data like IPs, hostnames, and credentials.
// Each word is checked independently and tracked in statistics.
func (s *Sanitizer) sanitizeCommentContent(content string) string {
	if content == "" {
		return content
	}

	// Split comment into words and sanitize each potential sensitive value
	words := strings.Fields(content)
	for i, word := range words {
		s.stats.TotalFields++
		should, rule := s.engine.ShouldRedactValue("comment", word)
		if should {
			redacted := s.engine.RedactWithRule(rule, "comment", word)
			if redacted != word {
				s.stats.RedactedFields++
				if rule.Name != "" {
					s.stats.RedactionsByType[rule.Name]++
				}
				words[i] = redacted
			} else {
				s.stats.SkippedFields++
			}
		} else {
			s.stats.SkippedFields++
		}
	}

	return strings.Join(words, " ")
}

// SanitizeStruct uses reflection to sanitize a struct in place.
// This is useful for sanitizing parsed model structs before re-encoding.
func (s *Sanitizer) SanitizeStruct(v any) error {
	return s.sanitizeReflect(reflect.ValueOf(v), nil, -1)
}

// sanitizeReflect recursively sanitizes a reflected value. The dotted field
// path is represented as a pathStack of segments plus an optional slice
// sliceIdx (>=0 when the value is the N-th element of an enclosing slice).
// The path is materialized into a single dotted string only at the leaf
// (reflect.String / reflect.Map) where the rule lookup actually happens.
// See issue #149 for motivation — the previous Sprintf-per-slice-element
// approach produced tens of thousands of short-lived strings per call.
func (s *Sanitizer) sanitizeReflect(v reflect.Value, pathStack []string, sliceIdx int) error {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		return s.sanitizeReflect(v.Elem(), pathStack, sliceIdx)
	}

	switch v.Kind() {
	case reflect.Struct:
		return s.sanitizeReflectStruct(v, pathStack, sliceIdx)
	case reflect.Slice:
		for i := range v.Len() {
			if err := s.sanitizeReflect(v.Index(i), pathStack, i); err != nil {
				return err
			}
		}
	case reflect.Map:
		return s.sanitizeReflectMap(v, pathStack, sliceIdx)
	case reflect.String:
		if v.CanSet() {
			s.stats.TotalFields++
			original := v.String()
			// Materialize the dotted path only now — most non-string
			// recursion never reaches this branch.
			path := joinReflectPath(pathStack, sliceIdx)
			sanitized := s.sanitizeValue(path, original)
			if sanitized != original {
				v.SetString(sanitized)
			}
		}
	default:
		// No-op for primitive kinds (bool, int family, float family,
		// complex, uintptr, chan, func, interface, array,
		// unsafe.Pointer). Sanitization only applies to strings, and
		// containers (struct/slice/map) are recursed into above. The
		// primitive no-op is intentional — adding sanitization to a
		// bool field would not produce a meaningful redaction.
	}

	return nil
}

// sanitizeReflectStruct walks the exported fields of a struct value. When the
// struct is a slice element, the terminal path segment is fused with "[i]"
// so string leaves see the canonical "parent.field[i].child" shape rather
// than "parent.field.[i].child".
func (s *Sanitizer) sanitizeReflectStruct(v reflect.Value, pathStack []string, sliceIdx int) error {
	t := v.Type()
	// Reuse pathStack directly when there is no index to fuse — the loop
	// below allocates a fresh child slice per iteration so siblings never
	// alias each other.
	localStack := pathStack
	if sliceIdx >= 0 && len(localStack) > 0 {
		indexed := localStack[len(localStack)-1] + "[" + strconv.Itoa(sliceIdx) + "]"
		newStack := make([]string, len(localStack))
		copy(newStack, localStack)
		newStack[len(newStack)-1] = indexed
		localStack = newStack
	}
	for i := range v.NumField() {
		field := v.Field(i)
		fieldType := t.Field(i)

		if !field.CanSet() || fieldType.Name == "XMLName" {
			continue
		}

		// Allocate a fresh child stack per field so sibling recursions
		// never share backing storage. This keeps paths correct when a
		// nested struct appends its own segments.
		segment := reflectFieldSegment(fieldType)
		childStack := make([]string, len(localStack)+1)
		copy(childStack, localStack)
		childStack[len(localStack)] = segment
		if err := s.sanitizeReflect(field, childStack, -1); err != nil {
			return err
		}
	}
	return nil
}

// reflectFieldSegment returns the path segment for a struct field: the xml
// tag name when present (minus any comma-options), otherwise the Go field
// name. A xml tag of "-" is ignored (the field still contributes its Go
// name — callers that want true exclusion must use CanSet/XMLName gates).
func reflectFieldSegment(fieldType reflect.StructField) string {
	xmlTag := fieldType.Tag.Get("xml")
	if xmlTag == "" || xmlTag == "-" {
		return fieldType.Name
	}
	if comma := strings.IndexByte(xmlTag, ','); comma >= 0 {
		if comma > 0 {
			return xmlTag[:comma]
		}
		return fieldType.Name
	}
	return xmlTag
}

// sanitizeReflectMap handles map values: recursion is skipped for
// struct/pointer-valued maps (see GOTCHAS §14.4) because map entries are not
// addressable, and string-valued entries are rewritten in place.
func (s *Sanitizer) sanitizeReflectMap(v reflect.Value, pathStack []string, sliceIdx int) error {
	elemKind := v.Type().Elem().Kind()
	if elemKind == reflect.Struct || elemKind == reflect.Pointer {
		// Log a warning so future schema additions that embed secrets behind
		// such a path surface the gap instead of silently shipping cleartext
		// through the reflection consumer flow. The raw-XML SanitizeXML path
		// is unaffected — it operates on element names, not Go types.
		if s.logger != nil {
			s.logger.Warn(
				"sanitize reflect: skipping map with struct/pointer values",
				"path", joinReflectPath(pathStack, sliceIdx),
				"type", v.Type().String(),
			)
		}
		return nil
	}
	for _, key := range v.MapKeys() {
		mapValue := v.MapIndex(key)
		if mapValue.Kind() != reflect.String || !mapValue.CanInterface() {
			continue
		}
		keyStr := fmt.Sprintf("%v", key.Interface())
		s.stats.TotalFields++
		original := mapValue.String()
		sanitized := s.sanitizeValue(keyStr, original)
		if sanitized != original {
			v.SetMapIndex(key, reflect.ValueOf(sanitized))
		}
	}
	return nil
}

// joinReflectPath flattens a reflect pathStack into a dotted field name,
// splicing in the current slice index when present. Callers that are about
// to consult the rule engine must use this helper so that the materialized
// path matches the historic "parent.field[i]" shape.
func joinReflectPath(pathStack []string, sliceIdx int) string {
	if len(pathStack) == 0 {
		if sliceIdx >= 0 {
			return "[" + strconv.Itoa(sliceIdx) + "]"
		}
		return ""
	}
	if sliceIdx < 0 {
		return strings.Join(pathStack, ".")
	}
	// Fuse "[i]" onto the terminal segment so slices over a named field
	// render as "parent.field[i]" rather than "parent.field.[i]".
	last := pathStack[len(pathStack)-1] + "[" + strconv.Itoa(sliceIdx) + "]"
	if len(pathStack) == 1 {
		return last
	}
	return strings.Join(pathStack[:len(pathStack)-1], ".") + "." + last
}

// escapeXMLText uses the stdlib xml.EscapeText to properly escape XML character data.
// This handles all XML-invalid control characters and edge cases.
// xml.EscapeText only errors if the writer fails; bytes.Buffer.Write never fails,
// so the error path is unreachable under normal conditions.
func escapeXMLText(s string) string {
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if err := xml.EscapeText(buf, []byte(s)); err != nil {
		// bytes.Buffer.Write should never fail. Log the error to avoid silent
		// fallback to unescaped XML, which could produce malformed output.
		log.Printf("sanitizer: xml.EscapeText failed (len=%d): %v", len(s), err)
		return s
	}
	return buf.String()
}

// escapeXMLAttr escapes a string for use in XML attribute values.
// Uses stdlib xml.EscapeText which handles all special characters including quotes.
func escapeXMLAttr(s string) string {
	return escapeXMLText(s)
}
