package builder

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"unicode"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/nao1215/markdown"
)

// metadataNone is written under a structured metadata heading whose value
// holds no entries, so the heading is not left dangling.
const metadataNone = "None."

// writeAuditMetadata emits the final "Audit Metadata" section when Metadata
// is non-empty. Scalar values (strings, numbers, booleans and lists of
// strings) share one key/value table. A struct or a list of structs cannot be
// read from a table cell: the default formatter prints it as unlabeled Go
// syntax such as {2 2 0 1} or [{webgui 443 lan}] (#949, #990). Each such
// value therefore gets a subsection of its own after the table, titled after
// its key. Keys are sorted for determinism.
func writeAuditMetadata(md *markdown.Markdown, cc *common.ComplianceResults) {
	if len(cc.Metadata) == 0 {
		return
	}
	md.H2("Audit Metadata")

	// A key goes to one of the two outputs, so neither slice has a known
	// final size (AGENTS.md item 7).
	var structuredKeys []string
	metadataTable := markdown.TableSet{Header: []string{"Key", colValue}}
	for _, key := range slices.Sorted(maps.Keys(cc.Metadata)) {
		value := cc.Metadata[key]
		if isStructuredMetadata(value) {
			structuredKeys = append(structuredKeys, key)
			continue
		}
		metadataTable.Rows = append(metadataTable.Rows, []string{
			formatters.EscapeTableContent(key),
			formatMetadataValue(value),
		})
	}
	if len(metadataTable.Rows) > 0 {
		md.Table(metadataTable)
	}
	for _, key := range structuredKeys {
		writeStructuredMetadata(md, key, cc.Metadata[key])
	}
}

// isStructuredMetadata reports whether value is a struct or a list of structs,
// which the key/value table cannot show with its fields labeled. A value that
// formats itself through fmt.Stringer, such as time.Time, stays a scalar.
func isStructuredMetadata(value any) bool {
	if value == nil {
		return false
	}
	if _, ok := value.(fmt.Stringer); ok {
		return false
	}
	t := indirectType(reflect.TypeOf(value))
	if t.Kind() == reflect.Struct {
		return true
	}
	if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		return indirectType(t.Elem()).Kind() == reflect.Struct
	}
	return false
}

// indirectType strips every pointer layer from t.
func indirectType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// writeStructuredMetadata emits one subsection for a struct or list-of-struct
// metadata value. Recommendations carry a list inside each record, which no
// table cell can hold, so they render as nested bullets. Every other struct
// renders as a labeled Field/Value table and every other list of structs as a
// table with one column per field, so a structured key added later is
// labeled without a renderer of its own.
func writeStructuredMetadata(md *markdown.Markdown, key string, value any) {
	md.H3(humanizeMetadataKey(key))

	if recs, ok := value.([]audit.Recommendation); ok {
		writeRecommendations(md, recs)
		return
	}

	v := reflect.Indirect(reflect.ValueOf(value))
	switch {
	case !v.IsValid():
		md.PlainText(metadataNone).BlankLine()
	case v.Kind() == reflect.Struct:
		md.Table(structFieldTable(v))
	case v.Len() == 0:
		md.PlainText(metadataNone).BlankLine()
	default:
		md.Table(structListTable(v))
	}
}

// writeRecommendations renders one bullet per component with that component's
// recommendation strings as a nested list. The slice arrives sorted by
// component, and each component's strings sorted, from audit.addRecommendations.
func writeRecommendations(md *markdown.Markdown, recs []audit.Recommendation) {
	if len(recs) == 0 {
		md.PlainText(metadataNone).BlankLine()
		return
	}
	for _, rec := range recs {
		md.BulletList("**" + formatters.EscapeMarkdownValue(rec.Component) + "**")
		for _, text := range rec.Recommendations {
			md.PlainText("  - " + formatters.EscapeMarkdownValue(text))
		}
	}
	// A table ends with a blank line; end the list the same way so a
	// following heading is separated from it.
	md.BlankLine()
}

// structFieldTable renders one struct as a two-column Field/Value table with
// one row per exported field, in declaration order.
func structFieldTable(v reflect.Value) markdown.TableSet {
	table := markdown.TableSet{Header: []string{"Field", colValue}}
	for i := range v.NumField() {
		field := v.Type().Field(i)
		if !field.IsExported() {
			continue
		}
		table.Rows = append(table.Rows, []string{
			humanizeFieldName(field.Name),
			formatMetadataValue(v.Field(i).Interface()),
		})
	}
	return table
}

// structListTable renders a non-empty list of structs as a table with one
// column per exported field of the element type and one row per element.
func structListTable(list reflect.Value) markdown.TableSet {
	elemType := indirectType(list.Type().Elem())

	var columns []int
	var header []string
	for i := range elemType.NumField() {
		field := elemType.Field(i)
		if !field.IsExported() {
			continue
		}
		columns = append(columns, i)
		header = append(header, humanizeFieldName(field.Name))
	}

	table := markdown.TableSet{Header: header}
	for i := range list.Len() {
		elem := reflect.Indirect(list.Index(i))
		if !elem.IsValid() {
			continue
		}
		row := make([]string, 0, len(columns))
		for _, c := range columns {
			row = append(row, formatMetadataValue(elem.Field(c).Interface()))
		}
		table.Rows = append(table.Rows, row)
	}
	return table
}

// formatMetadataValue renders a metadata value as one table cell. A list of
// strings is joined with ", " so it reads as a list rather than as Go slice
// syntax, a struct nested inside a cell is written as labeled "Field: value"
// pairs, and anything else goes through the shared table escaper.
func formatMetadataValue(value any) string {
	if value == nil {
		return ""
	}
	if _, ok := value.(fmt.Stringer); ok {
		return formatters.EscapeTableContent(value)
	}

	v := reflect.Indirect(reflect.ValueOf(value))
	switch {
	case !v.IsValid():
		return ""
	case v.Kind() == reflect.Slice || v.Kind() == reflect.Array:
		parts := make([]string, 0, v.Len())
		for i := range v.Len() {
			parts = append(parts, formatMetadataValue(v.Index(i).Interface()))
		}
		return strings.Join(parts, ", ")
	case v.Kind() == reflect.Struct:
		var pairs []string
		for i := range v.NumField() {
			field := v.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			pairs = append(pairs, humanizeFieldName(field.Name)+": "+formatMetadataValue(v.Field(i).Interface()))
		}
		return strings.Join(pairs, ", ")
	default:
		return formatters.EscapeTableContent(v.Interface())
	}
}

// humanizeMetadataKey turns a snake_case metadata key into a section title:
// "configuration_summary" becomes "Configuration Summary".
func humanizeMetadataKey(key string) string {
	words := strings.Split(key, "_")
	for i, word := range words {
		if word == "" {
			continue
		}
		words[i] = strings.ToUpper(word[:1]) + word[1:]
	}
	return strings.TrimSpace(strings.Join(words, " "))
}

// humanizeFieldName splits a Go field name into words at its case boundaries,
// keeping acronym runs together: "InboundNATRules" becomes "Inbound NAT Rules"
// and "WANInterfaces" becomes "WAN Interfaces".
func humanizeFieldName(name string) string {
	runes := []rune(name)
	var b strings.Builder
	b.Grow(len(name) + len(name)/2)
	for i, r := range runes {
		if i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			nextIsLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			// A new word starts at an upper-case letter after a lower-case letter
			// or a digit, or at the last letter of an upper-case run of two or
			// more when a lower-case letter follows ("WAN|Interfaces"). A run of
			// one is a prefix, not an acronym: "IPv6" stays one word.
			acronymEnds := nextIsLower && i >= 2 && unicode.IsUpper(prev) && unicode.IsUpper(runes[i-2])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || acronymEnds {
				b.WriteByte(' ')
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}
