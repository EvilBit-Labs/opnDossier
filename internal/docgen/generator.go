// Package docgen provides auto-generation of model documentation from Go types.
// It uses reflection to introspect struct fields and generate markdown documentation
// suitable for users who want to understand the data model for custom integrations.
package docgen

import (
	"fmt"
	"reflect"
	"strings"
)

// FieldTags holds the extracted tag values for a struct field.
type FieldTags struct {
	JSON string
	YAML string
	XML  string
}

// FieldInfo represents documentation for a single struct field.
type FieldInfo struct {
	Name        string
	Type        string
	Path        string
	Tags        FieldTags
	IsOptional  bool
	IsNested    bool
	NestedType  string
	Description string
}

// DefaultMaxDepth is the default recursion depth limit for nested struct documentation.
const DefaultMaxDepth = 3

// Generator creates documentation from Go types using reflection.
type Generator struct {
	maxDepth int
}

// NewGenerator creates a new documentation generator.
func NewGenerator() *Generator {
	return &Generator{
		maxDepth: DefaultMaxDepth,
	}
}

// GenerateReference generates markdown documentation for the given value's type.
func (g *Generator) GenerateReference(v any) string {
	return g.GenerateReferenceWithPrefix(v, "")
}

// GenerateReferenceWithPrefix generates markdown documentation with a path prefix.
func (g *Generator) GenerateReferenceWithPrefix(v any, prefix string) string {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	fields := g.extractFields(t, prefix, 0)
	return g.formatMarkdown(t.Name(), fields)
}

// extractFields recursively extracts field information from a struct type.
func (g *Generator) extractFields(t reflect.Type, prefix string, depth int) []FieldInfo {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return nil
	}

	var fields []FieldInfo

	for i := range t.NumField() {
		field := t.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		info := g.buildFieldInfo(field, prefix, depth)
		fields = append(fields, info)
	}

	return fields
}

// buildFieldInfo creates FieldInfo for a single struct field.
// The depth parameter tracks recursion level for future nested documentation expansion.
func (g *Generator) buildFieldInfo(field reflect.StructField, prefix string, depth int) FieldInfo {
	_ = depth // Reserved for future recursive documentation expansion
	tags := g.extractTags(string(field.Tag))

	path := field.Name
	if prefix != "" {
		path = prefix + "." + field.Name
	}

	fieldType := g.formatType(field.Type)
	isOptional := strings.Contains(string(field.Tag), "omitempty")

	info := FieldInfo{
		Name:       field.Name,
		Type:       fieldType,
		Path:       path,
		Tags:       tags,
		IsOptional: isOptional,
	}

	// Check for nested struct types
	elemType := field.Type
	if elemType.Kind() == reflect.Ptr {
		elemType = elemType.Elem()
	}
	if elemType.Kind() == reflect.Slice {
		elemType = elemType.Elem()
		if elemType.Kind() == reflect.Ptr {
			elemType = elemType.Elem()
		}
	}

	if elemType.Kind() == reflect.Struct && elemType.Name() != "" {
		// Skip common types that aren't custom structs
		if !isBuiltinType(elemType.Name()) {
			info.IsNested = true
			info.NestedType = elemType.Name()
		}
	}

	return info
}

// extractTags parses struct tags and extracts JSON, YAML, and XML tag values.
func (g *Generator) extractTags(tagString string) FieldTags {
	tags := FieldTags{}

	tags.JSON = extractTagValue(tagString, "json")
	tags.YAML = extractTagValue(tagString, "yaml")
	tags.XML = extractTagValue(tagString, "xml")

	return tags
}

// extractTagValue extracts the value for a specific tag key from a tag string.
func extractTagValue(tagString, key string) string {
	tag := reflect.StructTag(tagString)
	value := tag.Get(key)
	if value == "" {
		return ""
	}

	// Remove options like ",omitempty"
	if idx := strings.Index(value, ","); idx != -1 {
		value = value[:idx]
	}

	return value
}

// formatType returns a human-readable type name.
func (g *Generator) formatType(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Ptr:
		return "*" + g.formatType(t.Elem())
	case reflect.Slice:
		return "[]" + g.formatType(t.Elem())
	case reflect.Map:
		return fmt.Sprintf("map[%s]%s", t.Key().Name(), g.formatType(t.Elem()))
	case reflect.Struct:
		if t.Name() != "" {
			return t.Name()
		}
		return "struct"
	default:
		return t.Name()
	}
}

// formatMarkdown generates markdown table from field information.
func (g *Generator) formatMarkdown(typeName string, fields []FieldInfo) string {
	var sb strings.Builder

	if typeName != "" {
		fmt.Fprintf(&sb, "## %s\n\n", typeName)
	}

	if len(fields) == 0 {
		sb.WriteString("*No exported fields*\n")
		return sb.String()
	}

	// Table header
	sb.WriteString("| Field | Type | JSON | YAML | Optional |\n")
	sb.WriteString("|-------|------|------|------|----------|\n")

	// Table rows
	for _, f := range fields {
		optional := ""
		if f.IsOptional {
			optional = "optional"
		}

		jsonTag := f.Tags.JSON
		if jsonTag == "-" {
			jsonTag = "*(skipped)*"
		}

		yamlTag := f.Tags.YAML
		if yamlTag == "" {
			yamlTag = "-"
		}

		fmt.Fprintf(&sb, "| `%s` | `%s` | `%s` | `%s` | %s |\n",
			f.Path, f.Type, jsonTag, yamlTag, optional)
	}

	return sb.String()
}

// isBuiltinType checks if a type name is a built-in Go type.
func isBuiltinType(name string) bool {
	builtins := map[string]bool{
		"Time":     true,
		"Duration": true,
	}
	return builtins[name]
}
