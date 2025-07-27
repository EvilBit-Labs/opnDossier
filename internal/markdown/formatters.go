// Package markdown provides advanced formatting and content enrichment for markdown generation.
package markdown

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	goldmark_parser "github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
)

// Badge represents a colorized status badge with emoji and text.
type Badge struct {
	Icon    string
	Text    string
	Color   string
	BGColor string
}

// Common badge definitions for security warnings and status indicators.
var (
	BadgeSuccess = Badge{
		Icon:    "✅",
		Text:    "OK",
		Color:   "#28a745",
		BGColor: "#d4edda",
	}
	BadgeFail = Badge{
		Icon:    "❌",
		Text:    "FAIL",
		Color:   "#dc3545",
		BGColor: "#f8d7da",
	}
	BadgeWarning = Badge{
		Icon:    "⚠️",
		Text:    "WARNING",
		Color:   "#ffc107",
		BGColor: "#fff3cd",
	}
	BadgeInfo = Badge{
		Icon:    "ℹ️",
		Text:    "INFO",
		Color:   "#17a2b8",
		BGColor: "#d1ecf1",
	}
	BadgeEnhanced = Badge{
		Icon:    "✨",
		Text:    "ENHANCED",
		Color:   "#6f42c1",
		BGColor: "#e2d9f3",
	}
	BadgeSecure = Badge{
		Icon:    "🔒",
		Text:    "SECURE",
		Color:   "#28a745",
		BGColor: "#d4edda",
	}
	BadgeInsecure = Badge{
		Icon:    "🔓",
		Text:    "INSECURE",
		Color:   "#dc3545",
		BGColor: "#f8d7da",
	}
)

// FormatValue automatically detects the type of value and formats it appropriately.
// Slices and structs are formatted as tables, scalars as code blocks or inline text.
func FormatValue(key string, value interface{}) string {
	if value == nil {
		return CodeBlock("", "nil")
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		return formatSliceValue(key, v)
	case reflect.Struct:
		return formatStructValue(key, v)
	case reflect.Map:
		return formatMapValue(key, v)
	case reflect.Ptr:
		if v.IsNil() {
			return CodeBlock("", "nil")
		}
		return FormatValue(key, v.Elem().Interface())
	default:
		return formatScalarValue(key, value)
	}
}

// formatSliceValue formats slice/array values as tables when appropriate.
func formatSliceValue(key string, v reflect.Value) string {
	if v.Len() == 0 {
		return fmt.Sprintf("**%s**: *empty*\n", key)
	}

	// Check if slice contains structs - format as table
	if v.Len() > 0 && v.Index(0).Kind() == reflect.Struct {
		return formatSliceAsTable(key, v)
	}

	// For simple slices, format as list
	var items []string
	for i := 0; i < v.Len(); i++ {
		item := fmt.Sprintf("%v", v.Index(i).Interface())
		items = append(items, "- "+item)
	}

	return fmt.Sprintf("**%s**:\n%s\n", key, strings.Join(items, "\n"))
}

// formatSliceAsTable formats a slice of structs as a markdown table.
func formatSliceAsTable(key string, v reflect.Value) string {
	if v.Len() == 0 {
		return fmt.Sprintf("**%s**: *empty*\n", key)
	}

	// Get headers from first struct
	firstItem := v.Index(0)
	headers := getStructFieldNames(firstItem)

	// Build rows
	var rows [][]string
	for i := 0; i < v.Len(); i++ {
		row := getStructFieldValues(v.Index(i))
		rows = append(rows, row)
	}

	return fmt.Sprintf("### %s\n\n%s\n", key, Table(headers, rows))
}

// formatStructValue formats struct values as key-value pairs or tables.
func formatStructValue(key string, v reflect.Value) string {
	t := v.Type()
	var lines []string

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Skip empty values for optional fields
		if isEmptyValue(fieldValue) {
			continue
		}

		fieldName := field.Name
		fieldText := fmt.Sprintf("**%s**: %v", fieldName, fieldValue.Interface())
		lines = append(lines, fieldText)
	}

	if len(lines) == 0 {
		return fmt.Sprintf("**%s**: *empty*\n", key)
	}

	return fmt.Sprintf("### %s\n\n%s\n", key, strings.Join(lines, "\n"))
}

// formatMapValue formats map values as tables or key-value pairs.
func formatMapValue(key string, v reflect.Value) string {
	if v.Len() == 0 {
		return fmt.Sprintf("**%s**: *empty*\n", key)
	}

	var lines []string
	for _, mapKey := range v.MapKeys() {
		mapValue := v.MapIndex(mapKey)
		line := fmt.Sprintf("**%v**: %v", mapKey.Interface(), mapValue.Interface())
		lines = append(lines, line)
	}

	return fmt.Sprintf("### %s\n\n%s\n", key, strings.Join(lines, "\n"))
}

// formatScalarValue formats scalar values as inline text or code blocks.
func formatScalarValue(key string, value interface{}) string {
	strValue := fmt.Sprintf("%v", value)

	// Check if it looks like configuration content
	if isConfigContent(strValue) {
		lang := detectConfigLanguage(strValue)
		return fmt.Sprintf("**%s**:\n\n%s\n", key, CodeBlock(lang, strValue))
	}

	return fmt.Sprintf("**%s**: %s\n", key, strValue)
}

// Table creates a formatted markdown table from headers and rows.
func Table(headers []string, rows [][]string) string {
	if len(headers) == 0 || len(rows) == 0 {
		return "*No data available*"
	}

	var builder strings.Builder

	// Write header row
	builder.WriteString("|")
	for _, header := range headers {
		builder.WriteString(fmt.Sprintf(" %s |", header))
	}
	builder.WriteString("\n")

	// Write separator row
	builder.WriteString("|")
	for range headers {
		builder.WriteString(" --- |")
	}
	builder.WriteString("\n")

	// Write data rows
	for _, row := range rows {
		builder.WriteString("|")
		for i, cell := range row {
			if i < len(headers) {
				builder.WriteString(fmt.Sprintf(" %s |", cell))
			}
		}
		// Fill in missing cells
		for i := len(row); i < len(headers); i++ {
			builder.WriteString(" |")
		}
		builder.WriteString("\n")
	}

	return builder.String()
}

// CodeBlock wraps content in a markdown code block with optional language hint.
func CodeBlock(language, content string) string {
	if language == "" {
		language = "text"
	}
	return fmt.Sprintf("```%s\n%s\n```", language, content)
}

// RenderBadge creates a markdown representation of a status badge.
func RenderBadge(badge Badge) string {
	return fmt.Sprintf("%s **%s**", badge.Icon, badge.Text)
}

// SecurityBadge returns an appropriate security badge based on the security level.
func SecurityBadge(secure, enhanced bool) Badge {
	if enhanced {
		return BadgeEnhanced
	}
	if secure {
		return BadgeSecure
	}
	return BadgeInsecure
}

// StatusBadge returns an appropriate status badge based on success/failure.
func StatusBadge(success bool) Badge {
	if success {
		return BadgeSuccess
	}
	return BadgeFail
}

// WarningBadge returns a warning badge for potential issues.
func WarningBadge() Badge {
	return BadgeWarning
}

// InfoBadge returns an info badge for informational content.
func InfoBadge() Badge {
	return BadgeInfo
}

// ValidateMarkdown validates markdown content using goldmark parser.
func ValidateMarkdown(content string) error {
	md := goldmark.New(
		goldmark.WithParserOptions(
			goldmark_parser.WithAutoHeadingID(),
		),
		goldmark.WithRendererOptions(
			html.WithHardWraps(),
		),
	)

	// Try to convert the markdown to validate syntax
	var buf strings.Builder
	if err := md.Convert([]byte(content), &buf); err != nil {
		return fmt.Errorf("failed to parse markdown content: %w", err)
	}

	return nil
}

// RenderMarkdown renders markdown content using goldmark for validation and formatting.
func RenderMarkdown(content string) (string, error) {
	md := goldmark.New(
		goldmark.WithParserOptions(
			goldmark_parser.WithAutoHeadingID(),
		),
		goldmark.WithRendererOptions(
			html.WithHardWraps(),
			html.WithXHTML(),
		),
	)

	var buf strings.Builder
	if err := md.Convert([]byte(content), &buf); err != nil {
		return "", fmt.Errorf("failed to render markdown: %w", err)
	}

	return buf.String(), nil
}

// Helper functions

// getStructFieldNames extracts field names from a struct value.
func getStructFieldNames(v reflect.Value) []string {
	t := v.Type()
	var names []string

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if field.IsExported() {
			names = append(names, field.Name)
		}
	}

	return names
}

// getStructFieldValues extracts field values from a struct value.
func getStructFieldValues(v reflect.Value) []string {
	var values []string

	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if field.IsExported() {
			fieldValue := v.Field(i)
			values = append(values, fmt.Sprintf("%v", fieldValue.Interface()))
		}
	}

	return values
}

// isEmptyValue checks if a reflect.Value is considered empty.
func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}

// isConfigContent checks if a string looks like configuration content.
func isConfigContent(s string) bool {
	// Check for common config patterns
	configPatterns := []string{
		`^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=`,       // key=value
		`^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*:`,       // key: value
		`^\s*\[[^\]]+\]`,                       // [section]
		`^\s*#.*$`,                             // comments
		`^\s*//.*$`,                            // comments
		`^\s*;.*$`,                             // comments
		`^\s*export\s+[A-Z_][A-Z0-9_]*=`,       // shell exports
		`^\s*set\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=`, // shell set commands
	}

	lines := strings.Split(s, "\n")
	configLineCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		for _, pattern := range configPatterns {
			if matched, _ := regexp.MatchString(pattern, line); matched {
				configLineCount++
				break
			}
		}
	}

	// Consider it config content if more than 30% of non-empty lines match config patterns
	nonEmptyLines := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			nonEmptyLines++
		}
	}

	if nonEmptyLines == 0 {
		return false
	}

	return float64(configLineCount)/float64(nonEmptyLines) > 0.3
}

// detectConfigLanguage attempts to detect the configuration language.
func detectConfigLanguage(content string) string {
	content = strings.ToLower(content)

	// Check for specific patterns
	if strings.Contains(content, "#!/bin/bash") || strings.Contains(content, "#!/bin/sh") ||
		strings.Contains(content, "export ") || strings.Contains(content, "set -") {
		return "shell"
	}

	if strings.Contains(content, "[") && strings.Contains(content, "]") &&
		strings.Contains(content, "=") {
		return "ini"
	}

	if strings.Contains(content, "{") && strings.Contains(content, "}") {
		return "json"
	}

	if strings.Contains(content, "---") || strings.Contains(content, "- ") {
		return "yaml"
	}

	if strings.Contains(content, "<?xml") || strings.Contains(content, "<config") {
		return "xml"
	}

	// Default to text for tunables and simple key-value pairs
	return "ini"
}
