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
	"sync"
	"unicode"

	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
)

// escapeBufPool pools the scratch buffers used by escapeXMLText, which runs
// once per XML text node / attribute value while streaming a whole
// config.xml. Every checkout MUST start at zero length: this is a redaction
// path, and a buffer that still held bytes from a prior config would leak
// them into the next result.
var escapeBufPool = sync.Pool{ //nolint:gochecknoglobals // scratch-buffer pool, no cross-call state
	New: func() any { return new(bytes.Buffer) },
}

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
	// The same charset reader the device parsers use. Without it encoding/xml
	// refuses any declaration other than UTF-8, so sanitize failed outright on
	// a real OPNsense config.xml, which declares us-ascii.
	decoder.CharsetReader = parser.CharsetReader

	var output strings.Builder
	output.Grow(len(data))
	// pathStack tracks element names at each depth. The cumulative dotted
	// path is materialized via strings.Join only at the CharData leaf where
	// ShouldRedactValue is consulted — most tokens (empty/whitespace CharData
	// and all Start/End transitions) skip the join entirely. This avoids
	// O(depth) string allocation per StartElement. See issue #148.
	var pathStack []string

	writeXMLDeclaration(&output, data)

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
			output.WriteString(replaceXMLIllegalChars(sanitizedComment))
			output.WriteString("-->")

		case xml.ProcInst:
			// Skip processing instructions (already handled XML declaration)
			if t.Target != "xml" {
				output.WriteString("<?")
				output.WriteString(replaceXMLIllegalChars(t.Target))
				output.WriteString(" ")
				output.WriteString(replaceXMLIllegalChars(string(t.Inst)))
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
//
// Field-name-driven rules (FieldPatterns match) are applied to the ENTIRE
// value in a single redaction call — a password rule must not fragment a
// multi-word passphrase into several independently-redacted pieces, and an
// "endpoint" field must redact its whole host:port value to one marker.
// Only when no field-name rule matches does this fall back to per-token
// value-based detection (redactValueTokens), so a whitespace/
// newline-separated multi-value field (an OPNsense alias <content> or
// pfSense alias <address>) has every member matched independently against
// the full rule set — a mix of a private IP, a public IP, and a CIDR in the
// same field is now fully redacted, rather than only the first rule type
// that happens to match anywhere in the value. See GOTCHAS re: the
// mixed-type alias leak this replaced.
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

	// Try full path first, then bare element name. Exact-match patterns
	// (e.g. "key") are anchored on the terminal path segment, so they match
	// either lookup: "system.key" on the full path and "key" on the bare
	// name both resolve to the same segment.
	if should, rule := s.engine.ShouldRedactFieldValue(fullPath, content); should {
		return s.redactWholeValue(rule, fullPath, content)
	}
	if should, rule := s.engine.ShouldRedactFieldValue(currentElement, content); should {
		return s.redactWholeValue(rule, currentElement, content)
	}

	return s.redactValueTokens(fullPath, content)
}

// redactWholeValue applies rule (already known to match via field name) to
// the entire value in a single redaction call, updating stats accordingly.
// Only count as redacted if the value actually changed. A Redactor may still
// return its input: the username rule declines system accounts via
// isSystemUser. Rules whose patterns are generic enough to match unrelated
// fields use FieldGuard instead, and never reach here at all.
func (s *Sanitizer) redactWholeValue(rule Rule, fieldName, content string) string {
	redacted := s.engine.RedactWithRule(rule, fieldName, content)
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

// replaceTokens applies fn to each run of non-space runes in s and copies the
// whitespace between them verbatim, so the caller's spacing survives redaction.
//
// Splitting a value into whitespace tokens before consulting any rule is what
// lets every member of a delimiter-separated multi-value field -- a
// newline-separated OPNsense alias <content>, a space-separated pfSense alias
// <address> -- be matched against the full rule set independently. It is
// deliberately not a bare substring scan: a token such as
// "203.0.113.1:51820" (a host:port endpoint) must not match as an IP, because
// IsPublicIP("203.0.113.1:51820") is false even though an unanchored IPv4
// regex would match the substring. Validating whole tokens preserves that.
//
// Space is unicode.IsSpace, matching what strings.Fields recognizes. A regexp
// \S+ is not equivalent: RE2 defines \s as ASCII-only ([\t\n\f\r ]), so a
// value separated by a no-break space or any other Unicode separator arrives
// at the detectors glued to its neighbour, fails every whole-token check, and
// is emitted verbatim.
func replaceTokens(s string, fn func(string) string) string {
	var b strings.Builder

	b.Grow(len(s))

	start := -1

	for i, r := range s {
		if !unicode.IsSpace(r) {
			if start < 0 {
				start = i
			}

			continue
		}

		if start >= 0 {
			b.WriteString(fn(s[start:i]))
			start = -1
		}

		b.WriteRune(r)
	}

	if start >= 0 {
		b.WriteString(fn(s[start:]))
	}

	return b.String()
}

// redactValueTokens splits content into whitespace-delimited tokens
// (preserving all original whitespace/newlines exactly — alias content is
// newline-structured, one member per line) and independently matches and
// redacts each token against the full rule set's value-detector path. A
// token matching no rule is left untouched. A single-token value (no
// internal whitespace) behaves identically to a direct whole-value
// ShouldRedactValue/RedactWithRule call. Reports one RedactedFields/
// SkippedFields event for the whole CharData leaf (matching the prior
// one-event-per-node accounting), but tracks RedactionsByType per rule
// actually used across all tokens.
func (s *Sanitizer) redactValueTokens(fieldName, content string) string {
	anyRedacted := false

	result := replaceTokens(content, func(token string) string {
		should, rule := s.engine.ShouldRedactValue(fieldName, token)
		if !should {
			return token
		}

		redacted := s.engine.RedactWithRule(rule, fieldName, token)
		if redacted == token {
			return token
		}

		anyRedacted = true
		if rule.Name != "" {
			s.stats.RedactionsByType[rule.Name]++
		}
		return redacted
	})

	if anyRedacted {
		s.stats.RedactedFields++
	} else {
		s.stats.SkippedFields++
	}

	return result
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
// Each whitespace-delimited token is checked independently. Surrounding
// whitespace is preserved verbatim, so a multi-line comment stays multi-line,
// and the result goes through escapeXMLComment before it is emitted.
func (s *Sanitizer) sanitizeCommentContent(content string) string {
	if content == "" {
		return content
	}

	redacted := replaceTokens(content, func(token string) string {
		s.stats.TotalFields++

		should, rule := s.engine.ShouldRedactValue("comment", token)
		if !should {
			s.stats.SkippedFields++
			return token
		}

		out := s.engine.RedactWithRule(rule, "comment", token)
		if out == token {
			s.stats.SkippedFields++
			return token
		}

		s.stats.RedactedFields++
		if rule.Name != "" {
			s.stats.RedactionsByType[rule.Name]++
		}
		return out
	})

	return escapeXMLComment(redacted)
}

// escapeXMLComment makes s safe to emit between the "<!--" and "-->"
// delimiters. XML 1.0 §2.5 forbids "--" inside a comment and forbids the
// content from ending in "-", which would fuse with the delimiter into "--->".
// A config carrying "<!-- migrated 2024- -->" is enough to hit it.
//
// A space neutralizes both. One ReplaceAll pass handles any run of dashes,
// since "--" becomes "- " and cannot recombine.
func escapeXMLComment(s string) string {
	if s == "" {
		return s
	}

	s = strings.ReplaceAll(s, "--", "- ")

	if strings.HasSuffix(s, "-") {
		s += " "
	}

	return s
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

// canonicalXMLDeclaration is the declaration written when the input's charset
// had to be re-labelled.
const canonicalXMLDeclaration = `<?xml version="1.0" encoding="UTF-8"?>`

// writeXMLDeclaration emits the sanitized document's XML declaration.
//
// A declaration naming UTF-8, or naming no encoding at all, is copied verbatim
// so output stays byte-identical for those inputs. Any other declared charset
// is replaced with a canonical UTF-8 declaration, because CharsetReader has
// already decoded the document and every byte written from here is UTF-8.
// Copying the original would label the output with an encoding it is not in,
// which re-parses as mojibake for anything outside ASCII.
func writeXMLDeclaration(output *strings.Builder, data []byte) {
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("<?xml")) {
		return
	}

	idx := bytes.Index(data, []byte("?>"))
	if idx <= 0 {
		return
	}

	decl := data[:idx+2]
	if declaresNonUTF8Charset(decl) {
		output.WriteString(canonicalXMLDeclaration)
	} else {
		output.Write(decl)
	}

	output.WriteString("\n")
}

// declaresNonUTF8Charset reports whether decl names an encoding that is not
// UTF-8. A declaration with no encoding attribute is treated as UTF-8, the XML
// default and what the sanitizer emits.
//
// The attribute is located the way encoding/xml locates it: the literal
// "encoding=" followed immediately by a quote. XML 1.0 allows whitespace around
// the "=" but Go's decoder does not, and a form the decoder does not recognize
// is never transcoded, so treating it as a declared charset here would relabel
// a document that was passed through untouched.
func declaresNonUTF8Charset(decl []byte) bool {
	lower := strings.ToLower(string(decl))

	const attr = "encoding="

	var (
		value string
		quote byte
	)

	for i := 0; ; {
		k := strings.Index(lower[i:], attr)
		if k < 0 {
			return false
		}

		i += k + len(attr)
		if i < len(lower) && (lower[i] == '"' || lower[i] == '\'') {
			quote = lower[i]
			value = lower[i+1:]

			break
		}
	}

	raw, _, ok := strings.Cut(value, string(quote))
	if !ok {
		return false
	}

	// Mirror CharsetReader's normalization: it treats UTF_8 as UTF-8 and passes
	// those bytes through untouched, so relabelling that declaration would
	// rewrite a document the sanitizer never transcoded.
	charset := strings.ReplaceAll(strings.TrimSpace(raw), "_", "-")

	switch charset {
	case "utf-8", "utf8", "":
		return false
	default:
		return true
	}
}

// replaceXMLIllegalChars substitutes U+FFFD for every rune outside the XML 1.0
// Char production, matching what xml.EscapeText already does for character
// data.
//
// Comment and processing-instruction content cannot be routed through
// xml.EscapeText: neither construct interprets markup, so escaping "<" and "&"
// inside them would corrupt the text. They are still bound by the Char
// production, and encoding/xml does not enforce it for either one — it rejects
// an illegal character inside CharData or an attribute value at parse time, but
// hands back Comment and ProcInst content verbatim. Emitting that unchanged
// yields a document Go re-reads happily while libxml2 ("invalid xmlChar value")
// and expat ("not well-formed") both reject it, breaking the config.xml-in,
// config.xml-out contract at exit 0.
//
// XML 1.0 provides no escape for these characters — not even a numeric
// reference — so substitution is the only way to emit a loadable document.
func replaceXMLIllegalChars(s string) string {
	if !strings.ContainsFunc(s, isXMLIllegalRune) {
		return s
	}

	return strings.Map(func(r rune) rune {
		if isXMLIllegalRune(r) {
			return '�'
		}

		return r
	}, s)
}

// isXMLIllegalRune reports whether r falls outside the XML 1.0 §2.2 Char
// production:
//
//	Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
//

func isXMLIllegalRune(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return false
	case r >= 0x20 && r <= 0xD7FF:
		return false
	case r >= 0xE000 && r <= 0xFFFD:
		return false
	case r >= 0x10000 && r <= 0x10FFFF:
		return false
	default:
		return true
	}
}

// escapeXMLText uses the stdlib xml.EscapeText to properly escape XML character data.
// This handles all XML-invalid control characters and edge cases.
// xml.EscapeText only errors if the writer fails; bytes.Buffer.Write never fails,
// so the error path is unreachable under normal conditions.
func escapeXMLText(s string) string {
	//nolint:errcheck // Type assertion always succeeds; pool.New guarantees *bytes.Buffer
	buf := escapeBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer escapeBufPool.Put(buf)
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
