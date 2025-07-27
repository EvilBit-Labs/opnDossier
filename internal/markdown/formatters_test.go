package markdown

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBadgeConstants(t *testing.T) {
	// Test that all badge constants are properly defined
	assert.Equal(t, "✅", BadgeSuccess().Icon)
	assert.Equal(t, "OK", BadgeSuccess().Text)

	assert.Equal(t, "❌", BadgeFail().Icon)
	assert.Equal(t, "FAIL", BadgeFail().Text)

	assert.Equal(t, "⚠️", BadgeWarning().Icon)
	assert.Equal(t, "WARNING", BadgeWarning().Text)

	assert.Equal(t, "ℹ️", BadgeInfo().Icon)
	assert.Equal(t, "INFO", BadgeInfo().Text)

	assert.Equal(t, "✨", BadgeEnhanced().Icon)
	assert.Equal(t, "ENHANCED", BadgeEnhanced().Text)

	assert.Equal(t, "🔒", BadgeSecure().Icon)
	assert.Equal(t, "SECURE", BadgeSecure().Text)

	assert.Equal(t, "🔓", BadgeInsecure().Icon)
	assert.Equal(t, "INSECURE", BadgeInsecure().Text)
}

func TestFormatValue(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    interface{}
		expected string
	}{
		{
			name:     "nil value",
			key:      "test",
			value:    nil,
			expected: "```text\nnil\n```",
		},
		{
			name:     "string value",
			key:      "hostname",
			value:    "test-server",
			expected: "**hostname**: test-server\n",
		},
		{
			name:     "int value",
			key:      "port",
			value:    8080,
			expected: "**port**: 8080\n",
		},
		{
			name:     "bool value",
			key:      "enabled",
			value:    true,
			expected: "**enabled**: true\n",
		},
		{
			name:     "empty slice",
			key:      "items",
			value:    []string{},
			expected: "**items**: *empty*\n",
		},
		{
			name:     "string slice",
			key:      "servers",
			value:    []string{"server1", "server2"},
			expected: "**servers**:\n- server1\n- server2\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatValue(tt.key, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatValueStruct(t *testing.T) {
	type TestStruct struct {
		Name    string
		Port    int
		Enabled bool
		private string // should be ignored
	}

	s := TestStruct{
		Name:    "test",
		Port:    8080,
		Enabled: true,
		private: "ignored",
	}

	result := FormatValue("config", s)
	assert.Contains(t, result, "### config")
	assert.Contains(t, result, "**Name**: test")
	assert.Contains(t, result, "**Port**: 8080")
	assert.Contains(t, result, "**Enabled**: true")
	assert.NotContains(t, result, "private")
}

func TestFormatValueMap(t *testing.T) {
	m := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}

	result := FormatValue("settings", m)
	assert.Contains(t, result, "### settings")
	assert.Contains(t, result, "**key1**: value1")
	assert.Contains(t, result, "**key2**: 42")
}

func TestTable(t *testing.T) {
	headers := []string{"Name", "Port", "Status"}
	rows := [][]string{
		{"server1", "8080", "active"},
		{"server2", "8081", "inactive"},
	}

	result := Table(headers, rows)

	expected := `| Name | Port | Status |
| --- | --- | --- |
| server1 | 8080 | active |
| server2 | 8081 | inactive |
`
	assert.Equal(t, expected, result)
}

func TestTable_EmptyInput(t *testing.T) {
	// Test empty headers
	result := Table([]string{}, [][]string{{"data"}})
	assert.Equal(t, "*No data available*", result)

	// Test empty rows
	result = Table([]string{"Header"}, [][]string{})
	assert.Equal(t, "*No data available*", result)
}

func TestTable_UnevenRows(t *testing.T) {
	headers := []string{"Col1", "Col2", "Col3"}
	rows := [][]string{
		{"A", "B"},      // Missing one column
		{"C", "D", "E"}, // Complete row
	}

	result := Table(headers, rows)
	assert.Contains(t, result, "| A | B | |")
	assert.Contains(t, result, "| C | D | E |")
}

func TestCodeBlock(t *testing.T) {
	content := "console.log('hello');"
	result := CodeBlock("javascript", content)
	expected := "```javascript\nconsole.log('hello');\n```"
	assert.Equal(t, expected, result)

	// Test without language
	result = CodeBlock("", content)
	expected = "```text\nconsole.log('hello');\n```"
	assert.Equal(t, expected, result)
}

func TestRenderBadge(t *testing.T) {
	badge := Badge{
		Icon: "🔒",
		Text: "SECURE",
	}

	result := RenderBadge(badge)
	expected := "🔒 **SECURE**"
	assert.Equal(t, expected, result)
}

func TestSecurityBadge(t *testing.T) {
	// Test enhanced security
	badge := SecurityBadge(true, true)
	assert.Equal(t, BadgeEnhanced(), badge)

	// Test secure but not enhanced
	badge = SecurityBadge(true, false)
	assert.Equal(t, BadgeSecure(), badge)

	// Test insecure
	badge = SecurityBadge(false, false)
	assert.Equal(t, BadgeInsecure(), badge)
}

func TestStatusBadge(t *testing.T) {
	// Test success
	badge := StatusBadge(true)
	assert.Equal(t, BadgeSuccess(), badge)

	// Test failure
	badge = StatusBadge(false)
	assert.Equal(t, BadgeFail(), badge)
}

func TestWarningBadge(t *testing.T) {
	badge := WarningBadge()
	assert.Equal(t, BadgeWarning(), badge)
}

func TestInfoBadge(t *testing.T) {
	badge := InfoBadge()
	assert.Equal(t, BadgeInfo(), badge)
}

func TestValidateMarkdown(t *testing.T) {
	// Test valid markdown
	validMarkdown := "# Hello World\n\nThis is **bold** text."
	err := ValidateMarkdown(validMarkdown)
	assert.NoError(t, err)

	// Test simple markdown
	simpleMarkdown := "Just plain text"
	err = ValidateMarkdown(simpleMarkdown)
	assert.NoError(t, err)
}

func TestRenderMarkdown(t *testing.T) {
	markdown := "# Hello\n\nThis is **bold**."
	result, err := RenderMarkdown(markdown)
	require.NoError(t, err)
	assert.Contains(t, result, "<h1")
	assert.Contains(t, result, "<strong>bold</strong>")
}

func TestGetStructFieldNames(t *testing.T) {
	type TestStruct struct {
		PublicField  string
		AnotherField int
		_            string // should be ignored
	}

	v := reflect.ValueOf(TestStruct{})
	names := getStructFieldNames(v)

	assert.Contains(t, names, "PublicField")
	assert.Contains(t, names, "AnotherField")
	assert.NotContains(t, names, "privateField")
}

func TestGetStructFieldValues(t *testing.T) {
	type TestStruct struct {
		Name string
		Age  int
	}

	s := TestStruct{Name: "John", Age: 30}
	v := reflect.ValueOf(s)
	values := getStructFieldValues(v)

	assert.Equal(t, []string{"John", "30"}, values)
}

func TestIsEmptyValue(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected bool
	}{
		{"empty string", "", true},
		{"non-empty string", "hello", false},
		{"zero int", 0, true},
		{"non-zero int", 42, false},
		{"false bool", false, true},
		{"true bool", true, false},
		{"empty slice", []string{}, true},
		{"non-empty slice", []string{"item"}, false},
		{"nil pointer", (*string)(nil), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := reflect.ValueOf(tt.value)
			result := isEmptyValue(v)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsConfigContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "key-value config",
			content:  "server_name=example.com\nport=8080\n# comment",
			expected: true,
		},
		{
			name:     "yaml-style config",
			content:  "server:\n  name: example.com\n  port: 8080",
			expected: true,
		},
		{
			name:     "shell script",
			content:  "#!/bin/bash\nexport PATH=/usr/bin\nset -e",
			expected: true,
		},
		{
			name:     "plain text",
			content:  "This is just plain text with no configuration patterns.",
			expected: false,
		},
		{
			name:     "empty string",
			content:  "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isConfigContent(tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectConfigLanguage(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "shell script",
			content:  "#!/bin/bash\nexport PATH=/usr/bin",
			expected: "shell",
		},
		{
			name:     "ini file",
			content:  "[section]\nkey=value",
			expected: "ini",
		},
		{
			name:     "json",
			content:  `{"key": "value"}`,
			expected: "json",
		},
		{
			name:     "yaml",
			content:  "---\nkey: value\n- item",
			expected: "yaml",
		},
		{
			name:     "xml",
			content:  "<?xml version=\"1.0\"?>\n<config></config>",
			expected: "xml",
		},
		{
			name:     "unknown format",
			content:  "key=value\nother=setting",
			expected: "ini",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectConfigLanguage(tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}
