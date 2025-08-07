package model

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterfaceList_MarshalXML(t *testing.T) {
	tests := []struct {
		name     string
		input    InterfaceList
		expected string
	}{
		{
			name:     "single interface",
			input:    InterfaceList{"lan"},
			expected: `<test><interface>lan</interface></test>`,
		},
		{
			name:  "multiple interfaces",
			input: InterfaceList{"lan", "wan", "opt1"},
			// Note: Go's XML marshaler creates separate elements for slice items.
			// In contrast, the unmarshaling logic can handle both multiple <interface> elements
			// and a single <interface> element with comma-separated values. Marshaling, however,
			// always produces separate elements for each item in the slice.
			expected: `<test><interface>lan</interface><interface>wan</interface><interface>opt1</interface></test>`,
		},
		{
			name:     "empty interface list",
			input:    InterfaceList{},
			expected: `<test></test>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			type TestStruct struct {
				XMLName   xml.Name      `xml:"test"`
				Interface InterfaceList `xml:"interface,omitempty"`
			}

			input := TestStruct{Interface: tt.input}
			result, err := xml.Marshal(input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

func TestInterfaceList_String(t *testing.T) {
	tests := []struct {
		name     string
		input    InterfaceList
		expected string
	}{
		{
			name:     "single interface",
			input:    InterfaceList{"lan"},
			expected: "lan",
		},
		{
			name:     "multiple interfaces",
			input:    InterfaceList{"lan", "wan", "opt1"},
			expected: "lan,wan,opt1",
		},
		{
			name:     "empty interface list",
			input:    InterfaceList{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInterfaceList_Contains(t *testing.T) {
	il := InterfaceList{"lan", "wan", "opt1"}

	assert.True(t, il.Contains("lan"))
	assert.True(t, il.Contains("wan"))
	assert.True(t, il.Contains("opt1"))
	assert.False(t, il.Contains("dmz"))
	assert.False(t, il.Contains(""))

	// Test empty interface list
	empty := InterfaceList{}
	assert.False(t, empty.Contains("lan"))
}

func TestInterfaceList_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		input    InterfaceList
		expected bool
	}{
		{
			name:     "empty interface list",
			input:    InterfaceList{},
			expected: true,
		},
		{
			name:     "single interface",
			input:    InterfaceList{"lan"},
			expected: false,
		},
		{
			name:     "multiple interfaces",
			input:    InterfaceList{"lan", "wan"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRule_InterfaceList_Integration(t *testing.T) {
	// Test that Rule correctly uses InterfaceList for XML parsing
	xmlData := `
	<rule>
		<type>pass</type>
		<interface>opt1,opt2,lan</interface>
		<ipprotocol>inet</ipprotocol>
		<source>
			<network>any</network>
		</source>
		<destination>
			<network>any</network>
		</destination>
		<descr>Test rule with comma-separated interfaces</descr>
	</rule>`

	var rule Rule
	err := xml.Unmarshal([]byte(xmlData), &rule)
	require.NoError(t, err)

	assert.Equal(t, "pass", rule.Type)
	assert.Equal(t, InterfaceList{"opt1", "opt2", "lan"}, rule.Interface)
	assert.Equal(t, "inet", rule.IPProtocol)
	assert.Equal(t, "Test rule with comma-separated interfaces", rule.Descr)

	// Test that it correctly contains individual interfaces
	assert.True(t, rule.Interface.Contains("opt1"))
	assert.True(t, rule.Interface.Contains("opt2"))
	assert.True(t, rule.Interface.Contains("lan"))
	assert.False(t, rule.Interface.Contains("wan"))

	// Test string representation
	assert.Equal(t, "opt1,opt2,lan", rule.Interface.String())
}
