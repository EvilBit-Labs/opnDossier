package converter

import (
	"reflect"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

func TestMarkdownBuilder_EscapeTableContent(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{
			name:     "simple string",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "string with pipe",
			input:    "hello | world",
			expected: "hello \\| world",
		},
		{
			name:     "string with newline",
			input:    "hello\nworld",
			expected: "hello world",
		},
		{
			name:     "string with backslash",
			input:    "hello\\world",
			expected: "hello\\\\world",
		},
		{
			name:     "string with asterisks",
			input:    "hello *bold* world",
			expected: "hello \\*bold\\* world",
		},
		{
			name:     "string with underscores",
			input:    "hello _italic_ world",
			expected: "hello \\_italic\\_ world",
		},
		{
			name:     "string with backticks",
			input:    "hello `code` world",
			expected: "hello \\`code\\` world",
		},
		{
			name:     "string with square brackets",
			input:    "hello [link] world",
			expected: "hello \\[link\\] world",
		},
		{
			name:     "string with angle brackets",
			input:    "hello <tag> world",
			expected: "hello \\<tag\\> world",
		},
		{
			name:     "string with multiple special chars",
			input:    "hello | world\ntest\\data *bold* _italic_ `code` [link] <tag>",
			expected: "hello \\| world test\\\\data \\*bold\\* \\_italic\\_ \\`code\\` \\[link\\] \\<tag\\>",
		},
		{
			name:     "integer",
			input:    42,
			expected: "42",
		},
		{
			name:     "boolean",
			input:    true,
			expected: "true",
		},
		{
			name:     "nil",
			input:    nil,
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "whitespace only",
			input:    "   \t\n  ",
			expected: "",
		},
		{
			name:     "carriage return and newline",
			input:    "hello\r\nworld",
			expected: "hello world",
		},
		{
			name:     "carriage return only",
			input:    "hello\rworld",
			expected: "hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.EscapeTableContent(tt.input)
			if result != tt.expected {
				t.Errorf("EscapeTableContent() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestMarkdownBuilder_TruncateDescription(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name        string
		description string
		maxLength   int
		expected    string
	}{
		{
			name:        "short string",
			description: "hello",
			maxLength:   10,
			expected:    "hello",
		},
		{
			name:        "exact length",
			description: "hello world",
			maxLength:   11,
			expected:    "hello world",
		},
		{
			name:        "truncate with word boundary",
			description: "hello world test data",
			maxLength:   15,
			expected:    "hello world...",
		},
		{
			name:        "truncate without good word boundary",
			description: "verylongwordwithoutspaces",
			maxLength:   10,
			expected:    "verylongwo...",
		},
		{
			name:        "zero length",
			description: "hello",
			maxLength:   0,
			expected:    "",
		},
		{
			name:        "negative length",
			description: "hello",
			maxLength:   -5,
			expected:    "",
		},
		{
			name:        "empty string",
			description: "",
			maxLength:   10,
			expected:    "",
		},
		{
			name:        "word boundary too far back",
			description: "hello worldverylongwordwithoutspaces",
			maxLength:   25,
			expected:    "hello worldverylongwordwi...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.TruncateDescription(tt.description, tt.maxLength)
			if result != tt.expected {
				t.Errorf("TruncateDescription() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestMarkdownBuilder_IsLastInSlice(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name     string
		index    int
		slice    any
		expected bool
	}{
		{
			name:     "last element in slice",
			index:    2,
			slice:    []string{"a", "b", "c"},
			expected: true,
		},
		{
			name:     "not last element in slice",
			index:    1,
			slice:    []string{"a", "b", "c"},
			expected: false,
		},
		{
			name:     "single element slice",
			index:    0,
			slice:    []int{42},
			expected: true,
		},
		{
			name:     "empty slice",
			index:    0,
			slice:    []string{},
			expected: false,
		},
		{
			name:     "array",
			index:    1,
			slice:    [2]string{"a", "b"},
			expected: true,
		},
		{
			name:     "nil slice",
			index:    0,
			slice:    nil,
			expected: false,
		},
		{
			name:     "not a slice",
			index:    0,
			slice:    "hello",
			expected: false,
		},
		{
			name:     "index out of bounds",
			index:    5,
			slice:    []string{"a", "b"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.IsLastInSlice(tt.index, tt.slice)
			if result != tt.expected {
				t.Errorf("IsLastInSlice() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMarkdownBuilder_DefaultValue(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name       string
		value      any
		defaultVal any
		expected   any
	}{
		{
			name:       "non-empty string",
			value:      "hello",
			defaultVal: "default",
			expected:   "hello",
		},
		{
			name:       "empty string",
			value:      "",
			defaultVal: "default",
			expected:   "default",
		},
		{
			name:       "nil value",
			value:      nil,
			defaultVal: "default",
			expected:   "default",
		},
		{
			name:       "zero int",
			value:      0,
			defaultVal: 42,
			expected:   42,
		},
		{
			name:       "non-zero int",
			value:      10,
			defaultVal: 42,
			expected:   10,
		},
		{
			name:       "false bool",
			value:      false,
			defaultVal: true,
			expected:   true,
		},
		{
			name:       "true bool",
			value:      true,
			defaultVal: false,
			expected:   true,
		},
		{
			name:       "empty slice",
			value:      []string{},
			defaultVal: []string{"default"},
			expected:   []string{"default"},
		},
		{
			name:       "non-empty slice",
			value:      []string{"hello"},
			defaultVal: []string{"default"},
			expected:   []string{"hello"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.DefaultValue(tt.value, tt.defaultVal)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DefaultValue() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMarkdownBuilder_IsEmpty(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name     string
		value    any
		expected bool
	}{
		// String tests
		{name: "empty string", value: "", expected: true},
		{name: "non-empty string", value: "hello", expected: false},

		// Numeric tests
		{name: "zero int", value: 0, expected: true},
		{name: "non-zero int", value: 42, expected: false},
		{name: "zero float", value: 0.0, expected: true},
		{name: "non-zero float", value: 3.14, expected: false},
		{name: "zero uint", value: uint(0), expected: true},
		{name: "non-zero uint", value: uint(42), expected: false},

		// Boolean tests
		{name: "false bool", value: false, expected: true},
		{name: "true bool", value: true, expected: false},

		// Collection tests
		{name: "empty slice", value: []string{}, expected: true},
		{name: "non-empty slice", value: []string{"hello"}, expected: false},
		{name: "empty map", value: map[string]int{}, expected: true},
		{name: "non-empty map", value: map[string]int{"key": 1}, expected: false},
		{name: "empty array", value: [0]int{}, expected: true},
		{name: "non-empty array", value: [1]int{42}, expected: false},

		// Pointer and interface tests
		{name: "nil", value: nil, expected: true},
		{name: "nil pointer", value: (*string)(nil), expected: true},
		{name: "non-nil pointer", value: &[]string{"hello"}[0], expected: false},

		// Other types
		{name: "struct", value: struct{}{}, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.IsEmpty(tt.value)
			if result != tt.expected {
				t.Errorf("IsEmpty(%v) = %v, want %v", tt.value, result, tt.expected)
			}
		})
	}
}

func TestMarkdownBuilder_StringOperations(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name    string
		input   string
		toUpper string
		toLower string
		trimmed string
	}{
		{
			name:    "mixed case",
			input:   "Hello World",
			toUpper: "HELLO WORLD",
			toLower: "hello world",
			trimmed: "Hello World",
		},
		{
			name:    "with whitespace",
			input:   "  Hello World  ",
			toUpper: "  HELLO WORLD  ",
			toLower: "  hello world  ",
			trimmed: "Hello World",
		},
		{
			name:    "empty string",
			input:   "",
			toUpper: "",
			toLower: "",
			trimmed: "",
		},
		{
			name:    "only whitespace",
			input:   "   \t\n  ",
			toUpper: "   \t\n  ",
			toLower: "   \t\n  ",
			trimmed: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := builder.ToUpper(tt.input); result != tt.toUpper {
				t.Errorf("ToUpper(%q) = %q, want %q", tt.input, result, tt.toUpper)
			}
			if result := builder.ToLower(tt.input); result != tt.toLower {
				t.Errorf("ToLower(%q) = %q, want %q", tt.input, result, tt.toLower)
			}
			if result := builder.TrimSpace(tt.input); result != tt.trimmed {
				t.Errorf("TrimSpace(%q) = %q, want %q", tt.input, result, tt.trimmed)
			}
		})
	}
}

func TestMarkdownBuilder_BoolToString(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name     string
		input    bool
		expected string
	}{
		{
			name:     "true",
			input:    true,
			expected: "✅ Enabled",
		},
		{
			name:     "false",
			input:    false,
			expected: "❌ Disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.BoolToString(tt.input)
			if result != tt.expected {
				t.Errorf("BoolToString(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMarkdownBuilder_FormatBytes(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name     string
		input    int64
		expected string
	}{
		{
			name:     "bytes",
			input:    512,
			expected: "512 B",
		},
		{
			name:     "kilobytes",
			input:    1536, // 1.5 * 1024
			expected: "1.5 KiB",
		},
		{
			name:     "megabytes",
			input:    2097152, // 2 * 1024 * 1024
			expected: "2.0 MiB",
		},
		{
			name:     "gigabytes",
			input:    3221225472, // 3 * 1024^3
			expected: "3.0 GiB",
		},
		{
			name:     "terabytes",
			input:    4398046511104, // 4 * 1024^4
			expected: "4.0 TiB",
		},
		{
			name:     "zero bytes",
			input:    0,
			expected: "0 B",
		},
		{
			name:     "one byte",
			input:    1,
			expected: "1 B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.FormatBytes(tt.input)
			if result != tt.expected {
				t.Errorf("FormatBytes(%d) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMarkdownBuilder_SanitizeID(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "with spaces",
			input:    "hello world",
			expected: "hello-world",
		},
		{
			name:     "with special chars",
			input:    "hello@world!",
			expected: "hello-world",
		},
		{
			name:     "mixed case",
			input:    "Hello World",
			expected: "hello-world",
		},
		{
			name:     "with numbers",
			input:    "item123test",
			expected: "item123test",
		},
		{
			name:     "leading/trailing special chars",
			input:    "!!hello world!!",
			expected: "hello-world",
		},
		{
			name:     "only special chars",
			input:    "!@#$%",
			expected: "unnamed",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "unnamed",
		},
		{
			name:     "complex case",
			input:    "System Configuration: WAN Interface",
			expected: "system-configuration-wan-interface",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.SanitizeID(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNewMarkdownBuilderWithConfig(t *testing.T) {
	config := &model.OpnSenseDocument{}
	logger, err := logging.New(logging.Config{Level: "debug"})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	builder := NewMarkdownBuilderWithConfig(config, logger)
	if builder == nil {
		t.Error("Expected builder to be created")
	}
	// Note: Internal fields are now unexported for proper encapsulation
	// The builder is configured correctly but we cannot directly access the fields

	// Test with nil logger - builder should handle nil logger gracefully
	builder2 := NewMarkdownBuilderWithConfig(config, nil)
	if builder2 == nil {
		t.Error("Expected builder to be created even with nil logger")
	}
}

// Benchmark tests.
func BenchmarkEscapeTableContent(b *testing.B) {
	builder := NewMarkdownBuilder()
	content := "hello | world\nwith some | pipes and\nnewlines"

	b.ResetTimer()
	for b.Loop() {
		builder.EscapeTableContent(content)
	}
}

func BenchmarkTruncateDescription(b *testing.B) {
	builder := NewMarkdownBuilder()
	description := "This is a very long description that needs to be truncated at word boundaries when possible"

	b.ResetTimer()
	for b.Loop() {
		builder.TruncateDescription(description, 50)
	}
}

func BenchmarkIsEmpty(b *testing.B) {
	builder := NewMarkdownBuilder()
	testValues := []any{
		"",
		"hello",
		0,
		42,
		[]string{},
		[]string{"item"},
		nil,
		map[string]int{},
	}

	b.ResetTimer()
	for b.Loop() {
		for _, v := range testValues {
			builder.IsEmpty(v)
		}
	}
}
