package formatters

import (
	"reflect"
	"testing"
)

func TestEscapeTableContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content any
		want    string
	}{
		{"nil input", nil, ""},
		{"string with backslash", "test\\file", "test\\\\file"},
		{"string with asterisk", "test*file", "test\\*file"},
		{"string with underscore", "test_file", "test\\_file"},
		{"string with backtick", "test`file", "test\\`file"},
		{"string with brackets", "test[file]", "test\\[file\\]"},
		{"string with angle brackets", "test<file>", "test\\<file\\>"},
		{"string with pipe", "test|file", "test\\|file"},
		{"string with newlines", "test\nfile\r\nanother\rline", "test file another line"},
		{"integer", 42, "42"},
		{"empty string", "", ""},
		{"multiple escapes", "*test_file|name*", "\\*test\\_file\\|name\\*"},
		{"whitespace only", "  \n\r  ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := EscapeTableContent(tt.content)
			if got != tt.want {
				t.Errorf("EscapeTableContent(%v) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}

func TestTruncateDescription(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		description string
		maxLength   int
		want        string
	}{
		{"empty description", "", 10, ""},
		{"zero max length", "test", 0, ""},
		{"negative max length", "test", -1, ""},
		{"shorter than max", "test", 10, "test"},
		{"exact length", "test", 4, "test"},
		{"truncate without spaces", "teststring", 5, "tests..."},
		{"truncate with space", "hello world testing", 10, "hello..."},
		{"truncate with space at boundary", "hello world", 11, "hello world"},
		{"truncate but last space too far", "hello world testing", 8, "hello..."},
		{"single word longer than max", "verylongword", 5, "veryl..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := TruncateDescription(tt.description, tt.maxLength)
			if got != tt.want {
				t.Errorf("TruncateDescription(%q, %d) = %q, want %q", tt.description, tt.maxLength, got, tt.want)
			}
		})
	}
}

func TestIsLastInSlice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		index int
		slice any
		want  bool
	}{
		{"nil slice", 0, nil, false},
		{"not a slice", 0, "string", false},
		{"empty slice", 0, []int{}, false},
		{"single element - index 0", 0, []int{1}, true},
		{"single element - index 1", 1, []int{1}, false},
		{"multiple elements - last index", 2, []int{1, 2, 3}, true},
		{"multiple elements - middle index", 1, []int{1, 2, 3}, false},
		{"multiple elements - first index", 0, []int{1, 2, 3}, false},
		{"array type", 1, [2]int{1, 2}, true},
		{"out of bounds", 5, []int{1, 2, 3}, false},
		{"negative index", -1, []int{1, 2, 3}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsLastInSlice(tt.index, tt.slice)
			if got != tt.want {
				t.Errorf("IsLastInSlice(%d, %v) = %v, want %v", tt.index, tt.slice, got, tt.want)
			}
		})
	}
}

func TestDefaultValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		value      any
		defaultVal any
		want       any
	}{
		{"empty string uses default", "", "default", "default"},
		{"non-empty string uses value", "test", "default", "test"},
		{"nil uses default", nil, "default", "default"},
		{"zero int uses default", 0, 42, 42},
		{"non-zero int uses value", 5, 42, 5},
		{"false bool uses default", false, true, true},
		{"true bool uses value", true, false, true},
		{"empty slice uses default", []int{}, []int{1, 2, 3}, []int{1, 2, 3}},
		{"non-empty slice uses value", []int{4, 5}, []int{1, 2, 3}, []int{4, 5}},
		{"empty map uses default", map[string]int{}, map[string]int{"key": 1}, map[string]int{"key": 1}},
		{"non-empty map uses value", map[string]int{"test": 1}, map[string]int{"key": 1}, map[string]int{"test": 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := DefaultValue(tt.value, tt.defaultVal)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DefaultValue(%v, %v) = %v, want %v", tt.value, tt.defaultVal, got, tt.want)
			}
		})
	}
}

func TestIsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value any
		want  bool
	}{
		{"nil", nil, true},
		{"empty string", "", true},
		{"non-empty string", "test", false},
		{"empty slice", []int{}, true},
		{"non-empty slice", []int{1}, false},
		{"empty array", [0]int{}, true},
		{"non-empty array", [1]int{1}, false},
		{"empty map", map[string]int{}, true},
		{"non-empty map", map[string]int{"key": 1}, false},
		{"false bool", false, true},
		{"true bool", true, false},
		{"zero int", 0, true},
		{"non-zero int", 1, false},
		{"zero int8", int8(0), true},
		{"non-zero int8", int8(1), false},
		{"zero int16", int16(0), true},
		{"non-zero int16", int16(1), false},
		{"zero int32", int32(0), true},
		{"non-zero int32", int32(1), false},
		{"zero int64", int64(0), true},
		{"non-zero int64", int64(1), false},
		{"zero uint", uint(0), true},
		{"non-zero uint", uint(1), false},
		{"zero uint8", uint8(0), true},
		{"non-zero uint8", uint8(1), false},
		{"zero uint16", uint16(0), true},
		{"non-zero uint16", uint16(1), false},
		{"zero uint32", uint32(0), true},
		{"non-zero uint32", uint32(1), false},
		{"zero uint64", uint64(0), true},
		{"non-zero uint64", uint64(1), false},
		{"zero float32", float32(0), true},
		{"non-zero float32", float32(1.5), false},
		{"zero float64", float64(0), true},
		{"non-zero float64", float64(1.5), false},
		{"nil pointer", (*int)(nil), true},
		{"non-nil pointer", new(int), false},
		{"nil interface", interface{}(nil), true},
		{"non-nil interface", interface{}("test"), false},
		{"nil channel", chan int(nil), true},
		{"nil function", (func())(nil), true},
		{"struct", struct{}{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsEmpty(tt.value)
			if got != tt.want {
				t.Errorf("IsEmpty(%v) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestToUpper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		want string
	}{
		{"empty string", "", ""},
		{"lowercase", "hello", "HELLO"},
		{"uppercase", "HELLO", "HELLO"},
		{"mixed case", "Hello World", "HELLO WORLD"},
		{"numbers and symbols", "test123!@#", "TEST123!@#"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ToUpper(tt.s)
			if got != tt.want {
				t.Errorf("ToUpper(%q) = %q, want %q", tt.s, got, tt.want)
			}
		})
	}
}

func TestToLower(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		want string
	}{
		{"empty string", "", ""},
		{"lowercase", "hello", "hello"},
		{"uppercase", "HELLO", "hello"},
		{"mixed case", "Hello World", "hello world"},
		{"numbers and symbols", "TEST123!@#", "test123!@#"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ToLower(tt.s)
			if got != tt.want {
				t.Errorf("ToLower(%q) = %q, want %q", tt.s, got, tt.want)
			}
		})
	}
}

func TestTrimSpace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		want string
	}{
		{"empty string", "", ""},
		{"no spaces", "hello", "hello"},
		{"leading spaces", "  hello", "hello"},
		{"trailing spaces", "hello  ", "hello"},
		{"both sides", "  hello  ", "hello"},
		{"only spaces", "   ", ""},
		{"tabs and newlines", "\t\nhello\r\n\t", "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := TrimSpace(tt.s)
			if got != tt.want {
				t.Errorf("TrimSpace(%q) = %q, want %q", tt.s, got, tt.want)
			}
		})
	}
}

func TestBoolToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		val  bool
		want string
	}{
		{"true", true, "✅ Enabled"},
		{"false", false, "❌ Disabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := BoolToString(tt.val)
			if got != tt.want {
				t.Errorf("BoolToString(%v) = %q, want %q", tt.val, got, tt.want)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{"zero bytes", 0, "0 B"},
		{"single byte", 1, "1 B"},
		{"bytes less than 1024", 1023, "1023 B"},
		{"exactly 1 KiB", 1024, "1.0 KiB"},
		{"1.5 KiB", 1536, "1.5 KiB"},
		{"exactly 1 MiB", 1048576, "1.0 MiB"},
		{"exactly 1 GiB", 1073741824, "1.0 GiB"},
		{"exactly 1 TiB", 1099511627776, "1.0 TiB"},
		{"exactly 1 PiB", 1125899906842624, "1.0 PiB"},
		{"exactly 1 EiB", 1152921504606846976, "1.0 EiB"},
		{"large value", 5368709120, "5.0 GiB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatBytes(tt.bytes)
			if got != tt.want {
				t.Errorf("FormatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestSanitizeID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		want string
	}{
		{"empty string", "", "unnamed"},
		{"simple string", "hello", "hello"},
		{"uppercase", "HELLO", "hello"},
		{"mixed case", "Hello World", "hello-world"},
		{"numbers", "test123", "test123"},
		{"special characters", "test!@#$%^&*()", "test"},
		{"multiple spaces", "hello   world", "hello-world"},
		{"leading and trailing dashes", "---hello---", "hello"},
		{"only special characters", "!@#$%^&*()", "unnamed"},
		{"underscores", "hello_world_test", "hello-world-test"},
		{"dots", "hello.world.test", "hello-world-test"},
		{"complex string", "Test Name (v1.2.3)", "test-name-v1-2-3"},
		{"already clean", "hello-world", "hello-world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SanitizeID(tt.s)
			if got != tt.want {
				t.Errorf("SanitizeID(%q) = %q, want %q", tt.s, got, tt.want)
			}
		})
	}
}
