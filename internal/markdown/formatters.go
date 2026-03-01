// Package markdown provides advanced formatting and content enrichment for markdown generation.
package markdown

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	goldmark_parser "github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
)

const (
	checkboxChecked   = "[x]"
	checkboxUnchecked = "[ ]"
)

// Pre-compiled regex patterns for configuration content detection.
var (
	configKeyValuePattern     = regexp.MustCompile(`^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=`)       // key=value
	configKeyColonPattern     = regexp.MustCompile(`^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*:`)       // key: value
	configSectionPattern      = regexp.MustCompile(`^\s*\[[^\]]+\]`)                       // [section]
	configHashCommentPattern  = regexp.MustCompile(`^\s*#.*$`)                             // comments
	configSlashCommentPattern = regexp.MustCompile(`^\s*//.*$`)                            // comments
	configSemiCommentPattern  = regexp.MustCompile(`^\s*;.*$`)                             // comments
	configExportPattern       = regexp.MustCompile(`^\s*export\s+[A-Z_][A-Z0-9_]*=`)       // shell exports
	configSetPattern          = regexp.MustCompile(`^\s*set\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=`) // shell set commands
)

// Badge represents a colorized status badge with emoji and text.
type Badge struct {
	Icon    string
	Text    string
	Color   string
	BGColor string
}

// BadgeSuccess returns a Badge representing a successful status with a checkmark icon and green colors.
func BadgeSuccess() Badge {
	return Badge{
		Icon:    "✅",
		Text:    "OK",
		Color:   "#28a745",
		BGColor: "#d4edda",
	}
}

// BadgeFail returns a Badge representing a failure status with a red icon and background.
func BadgeFail() Badge {
	return Badge{
		Icon:    "❌",
		Text:    "FAIL",
		Color:   "#dc3545",
		BGColor: "#f8d7da",
	}
}

// BadgeWarning returns a Badge representing a warning status with a warning icon and yellow color scheme.
func BadgeWarning() Badge {
	return Badge{
		Icon:    "⚠️",
		Text:    "WARNING",
		Color:   "#ffc107",
		BGColor: "#fff3cd",
	}
}

// BadgeInfo returns a Badge representing informational status with an info icon and blue color scheme.
func BadgeInfo() Badge {
	return Badge{
		Icon:    "ℹ️",
		Text:    "INFO",
		Color:   "#17a2b8",
		BGColor: "#d1ecf1",
	}
}

// BadgeEnhanced returns a Badge representing an enhanced status with a sparkle emoji and purple color scheme.
func BadgeEnhanced() Badge {
	return Badge{
		Icon:    "✨",
		Text:    "ENHANCED",
		Color:   "#6f42c1",
		BGColor: "#e2d9f3",
	}
}

// BadgeSecure returns a Badge representing a secure status with a lock icon and green color scheme.
func BadgeSecure() Badge {
	return Badge{
		Icon:    "🔒",
		Text:    "SECURE",
		Color:   "#28a745",
		BGColor: "#d4edda",
	}
}

// BadgeInsecure returns a Badge representing an insecure status with a red color scheme and unlocked icon.
func BadgeInsecure() Badge {
	return Badge{
		Icon:    "🔓",
		Text:    "INSECURE",
		Color:   "#dc3545",
		BGColor: "#f8d7da",
	}
}

// FormatValue automatically detects the type of value and formats it appropriately.
// FormatValue returns a markdown-formatted string representation of the given value, choosing an appropriate format based on its type.
// Slices of structs are rendered as tables, other slices as lists, structs and maps as key-value pairs, and scalars as inline text or code blocks.
// Nil values are represented as a code block containing "nil".
func FormatValue(key string, value any) string {
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
	case reflect.Invalid:
		return CodeBlock("", "invalid")
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
		reflect.String, reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
		return formatScalarValue(key, value)
	default:
		return formatScalarValue(key, value)
	}
}

// formatSliceValue returns a markdown-formatted string for a slice or array value, rendering slices of structs as tables and other slices as bullet lists. Returns an "empty" indicator if the slice is empty.
func formatSliceValue(key string, v reflect.Value) string {
	if v.Len() == 0 {
		return fmt.Sprintf("**%s**: *empty*\n", key)
	}

	// Check if slice contains structs - format as table
	if v.Len() > 0 && v.Index(0).Kind() == reflect.Struct {
		return formatSliceAsTable(key, v)
	}

	// For simple slices, format as list
	items := make([]string, 0, v.Len())
	for i := range v.Len() {
		item := fmt.Sprintf("%v", v.Index(i).Interface())
		items = append(items, "- "+item)
	}

	return fmt.Sprintf("**%s**:\n%s\n", key, strings.Join(items, "\n"))
}

// formatSliceAsTable returns a markdown table representation of a slice of structs, using exported field names as headers and field values as rows. If the slice is empty, it returns a markdown line indicating emptiness.
func formatSliceAsTable(key string, v reflect.Value) string {
	if v.Len() == 0 {
		return fmt.Sprintf("**%s**: *empty*\n", key)
	}

	// Get headers from first struct
	firstItem := v.Index(0)
	headers := getStructFieldNames(firstItem)

	// Build rows
	var rows [][]string

	for i := range v.Len() {
		row := getStructFieldValues(v.Index(i))
		rows = append(rows, row)
	}

	return fmt.Sprintf("### %s\n\n%s\n", key, Table(headers, rows))
}

// formatStructValue returns a markdown-formatted section representing the non-empty exported fields of a struct as key-value pairs.
// If all exported fields are empty, it returns a markdown line indicating the struct is empty.
func formatStructValue(key string, v reflect.Value) string {
	t := v.Type()

	var lines []string

	for i := range v.NumField() {
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

// formatMapValue returns a markdown-formatted string representing a map's key-value pairs, or indicates if the map is empty.
func formatMapValue(key string, v reflect.Value) string {
	if v.Len() == 0 {
		return fmt.Sprintf("**%s**: *empty*\n", key)
	}

	mapKeys := v.MapKeys()
	lines := make([]string, 0, len(mapKeys))

	for _, mapKey := range v.MapKeys() {
		mapValue := v.MapIndex(mapKey)
		line := fmt.Sprintf("**%v**: %v", mapKey.Interface(), mapValue.Interface())
		lines = append(lines, line)
	}

	return fmt.Sprintf("### %s\n\n%s\n", key, strings.Join(lines, "\n"))
}

// formatScalarValue returns a markdown-formatted string for a scalar value, rendering it as inline text or as a code block if the value resembles configuration content.
func formatScalarValue(key string, value any) string {
	strValue := fmt.Sprintf("%v", value)

	// Check if it looks like configuration content
	if isConfigContent(strValue) {
		lang := detectConfigLanguage(strValue)
		return fmt.Sprintf("**%s**:\n\n%s\n", key, CodeBlock(lang, strValue))
	}

	return fmt.Sprintf("**%s**: %s\n", key, strValue)
}

// Table returns a markdown-formatted table using the provided headers and rows.
// If headers or rows are empty, it returns a message indicating no data is available.
func Table(headers []string, rows [][]string) string {
	if len(headers) == 0 || len(rows) == 0 {
		return "*No data available*"
	}

	var builder strings.Builder

	// Write header row
	builder.WriteString("|")

	for _, header := range headers {
		fmt.Fprintf(&builder, " %s |", header)
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
				fmt.Fprintf(&builder, " %s |", cell)
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

// CodeBlock returns the given content wrapped in a fenced markdown code block, using the specified language for syntax highlighting. If language is empty, "text" is used as the default.
func CodeBlock(language, content string) string {
	if language == "" {
		language = "text"
	}

	return fmt.Sprintf("```%s\n%s\n```", language, content)
}

// RenderBadge returns a markdown-formatted string representing the given badge, combining its icon and bolded text.
func RenderBadge(badge Badge) string {
	return fmt.Sprintf("%s **%s**", badge.Icon, badge.Text)
}

// SecurityBadge selects and returns a badge representing the security status.
// Returns an enhanced badge if enhanced is true, a secure badge if secure is true, or an insecure badge otherwise.
func SecurityBadge(secure, enhanced bool) Badge {
	if enhanced {
		return BadgeEnhanced()
	}

	if secure {
		return BadgeSecure()
	}

	return BadgeInsecure()
}

// StatusBadge returns a success badge if success is true, or a failure badge otherwise.
func StatusBadge(success bool) Badge {
	if success {
		return BadgeSuccess()
	}

	return BadgeFail()
}

// WarningBadge returns a Badge representing a warning status.
func WarningBadge() Badge {
	return BadgeWarning()
}

// InfoBadge returns a badge indicating informational status.
func InfoBadge() Badge {
	return BadgeInfo()
}

// ValidateMarkdown checks if the provided markdown content is syntactically valid.
// It returns an error if the content cannot be parsed as markdown.
func ValidateMarkdown(content string) error {
	md := goldmark.New(
		goldmark.WithExtensions(extension.Table),
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

// RenderMarkdown parses and renders markdown content to HTML using goldmark.
// Returns the rendered HTML string or an error if rendering fails.
// Raw HTML tags (e.g., <details>, <summary>) are preserved in the output.
func RenderMarkdown(content string) (string, error) {
	md := goldmark.New(
		goldmark.WithExtensions(extension.Table),
		goldmark.WithParserOptions(
			goldmark_parser.WithAutoHeadingID(),
		),
		goldmark.WithRendererOptions(
			html.WithHardWraps(),
			html.WithXHTML(),
			html.WithUnsafe(),
		),
	)

	var buf strings.Builder
	if err := md.Convert([]byte(content), &buf); err != nil {
		return "", fmt.Errorf("failed to render markdown: %w", err)
	}

	return buf.String(), nil
}

// Helper functions

// getStructFieldNames returns the names of all exported fields in the given struct value.
func getStructFieldNames(v reflect.Value) []string {
	t := v.Type()

	var names []string

	for i := range v.NumField() {
		field := t.Field(i)
		if field.IsExported() {
			names = append(names, field.Name)
		}
	}

	return names
}

// getStructFieldValues returns the string representations of all exported field values from the given struct value.
func getStructFieldValues(v reflect.Value) []string {
	var values []string

	for i := range v.NumField() {
		field := v.Type().Field(i)
		if field.IsExported() {
			fieldValue := v.Field(i)
			values = append(values, fmt.Sprintf("%v", fieldValue.Interface()))
		}
	}

	return values
}

// isEmptyValue returns true if the provided reflect.Value is considered empty, such as zero values, nil pointers, or empty collections.
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
	case reflect.Invalid,
		reflect.Complex64,
		reflect.Complex128,
		reflect.Chan,
		reflect.Func,
		reflect.Struct,
		reflect.UnsafePointer:
		return false
	default:
		return false
	}
}

// isConfigContent returns true if the input string resembles configuration file content based on common syntax patterns such as key-value pairs, section headers, or comments.
func isConfigContent(s string) bool {
	lines := strings.Split(s, "\n")
	configLineCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if configKeyValuePattern.MatchString(line) ||
			configKeyColonPattern.MatchString(line) ||
			configSectionPattern.MatchString(line) ||
			configHashCommentPattern.MatchString(line) ||
			configSlashCommentPattern.MatchString(line) ||
			configSemiCommentPattern.MatchString(line) ||
			configExportPattern.MatchString(line) ||
			configSetPattern.MatchString(line) {
			configLineCount++
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

	return float64(configLineCount)/float64(nonEmptyLines) > constants.ConfigThreshold
}

// detectConfigLanguage returns a string indicating the likely configuration language of the provided content based on common syntax markers.
// It distinguishes between shell, ini, json, yaml, and xml formats, defaulting to "ini" if no specific pattern is matched.
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

// GetPowerModeDescription converts power management mode acronyms to their full descriptions.
func GetPowerModeDescription(mode string) string {
	switch mode {
	case "hadp":
		return "High Performance with Dynamic Power Management"
	case "hiadp":
		return "High Performance with Adaptive Dynamic Power Management"
	case "adaptive":
		return "Adaptive Power Management"
	case "minimum":
		return "Minimum Power Consumption"
	case "maximum":
		return "Maximum Performance"
	default:
		return mode // Return original if unknown
	}
}

// IsTruthy determines if a value represents a "true" or "enabled" state.
// Handles various formats: "1", "yes", "true", "on", "enabled", etc.
// Treats -1 as "unset" and returns false for it.
func IsTruthy(value any) bool {
	if value == nil {
		return false
	}

	str := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", value)))

	switch str {
	case "1", "yes", "true", "on", "enabled", "active":
		return true
	case "0", "no", "false", "off", "disabled", "inactive", "", "-1":
		return false
	default:
		// Try to parse as float (handles both integers and floats)
		if num, err := strconv.ParseFloat(str, 64); err == nil {
			return num > 0 // Only positive numbers are truthy, -1 is falsy
		}
		return false
	}
}

// FormatBoolean formats a boolean value consistently using markdown checkboxes.
func FormatBoolean(value any) string {
	if IsTruthy(value) {
		return checkboxChecked
	}
	return checkboxUnchecked
}

// FormatBooleanWithUnset formats a boolean value, showing "unset" for -1 values.
func FormatBooleanWithUnset(value any) string {
	if value == nil {
		return checkboxUnchecked
	}

	str := strings.TrimSpace(fmt.Sprintf("%v", value))
	if str == "-1" {
		return "unset"
	}

	if IsTruthy(value) {
		return checkboxChecked
	}
	return checkboxUnchecked
}

// FormatUnixTimestamp converts a Unix timestamp string to an ISO 8601 formatted date.
func FormatUnixTimestamp(timestamp string) string {
	if timestamp == "" {
		return "-"
	}

	// Try to parse as float64 (handles both integer and decimal timestamps)
	ts, err := strconv.ParseFloat(timestamp, 64)
	if err != nil {
		return timestamp // Return original if parsing fails
	}

	// Convert to time.Time
	t := time.Unix(int64(ts), int64((ts-float64(int64(ts)))*float64(time.Second)))

	// Format as ISO 8601
	return t.Format("2006-01-02T15:04:05Z07:00")
}
