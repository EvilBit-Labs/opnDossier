// Package docgen provides auto-generation of model documentation.
package docgen

import (
	"strings"
	"testing"
)

// Test types for unit testing.
type simpleStruct struct {
	Name    string `json:"name"    yaml:"name"    xml:"name"`
	Age     int    `json:"age"     yaml:"age"     xml:"age"`
	Enabled bool   `json:"enabled" yaml:"enabled" xml:"enabled"`
}

type nestedStruct struct {
	ID     string       `json:"id"     yaml:"id"     xml:"id"`
	Config simpleStruct `json:"config" yaml:"config" xml:"config"`
}

type structWithSlice struct {
	Items []simpleStruct `json:"items" yaml:"items" xml:"items"`
}

type structWithMap struct {
	Metadata map[string]string `json:"metadata" yaml:"metadata" xml:"metadata"`
}

type structWithPointer struct {
	Optional *simpleStruct `json:"optional,omitempty" yaml:"optional,omitempty" xml:"optional,omitempty"`
}

type structWithPrivateFields struct {
	Public  string `json:"public"`
	private string //nolint:unused // intentionally unused for testing
}

func TestNewGenerator(t *testing.T) {
	t.Parallel()

	g := NewGenerator()
	if g == nil {
		t.Fatal("NewGenerator() returned nil")
	}
}

func TestGenerator_GenerateReference_SimpleStruct(t *testing.T) {
	t.Parallel()

	g := NewGenerator()
	result := g.GenerateReference(simpleStruct{})

	// Should contain field names
	if !strings.Contains(result, "Name") {
		t.Error("result should contain field 'Name'")
	}
	if !strings.Contains(result, "Age") {
		t.Error("result should contain field 'Age'")
	}
	if !strings.Contains(result, "Enabled") {
		t.Error("result should contain field 'Enabled'")
	}

	// Should contain types
	if !strings.Contains(result, "string") {
		t.Error("result should contain type 'string'")
	}
	if !strings.Contains(result, "int") {
		t.Error("result should contain type 'int'")
	}
	if !strings.Contains(result, "bool") {
		t.Error("result should contain type 'bool'")
	}

	// Should contain JSON tags
	if !strings.Contains(result, "name") {
		t.Error("result should contain json tag 'name'")
	}
}

func TestGenerator_GenerateReference_NestedStruct(t *testing.T) {
	t.Parallel()

	g := NewGenerator()
	result := g.GenerateReference(nestedStruct{})

	// Should contain parent field
	if !strings.Contains(result, "ID") {
		t.Error("result should contain field 'ID'")
	}
	if !strings.Contains(result, "Config") {
		t.Error("result should contain field 'Config'")
	}

	// Should indicate nested structure
	if !strings.Contains(result, "simpleStruct") {
		t.Error("result should reference nested type 'simpleStruct'")
	}
}

func TestGenerator_GenerateReference_StructWithSlice(t *testing.T) {
	t.Parallel()

	g := NewGenerator()
	result := g.GenerateReference(structWithSlice{})

	// Should contain slice field
	if !strings.Contains(result, "Items") {
		t.Error("result should contain field 'Items'")
	}

	// Should indicate slice type
	if !strings.Contains(result, "[]") {
		t.Error("result should indicate slice type with '[]'")
	}
}

func TestGenerator_GenerateReference_StructWithMap(t *testing.T) {
	t.Parallel()

	g := NewGenerator()
	result := g.GenerateReference(structWithMap{})

	// Should contain map field
	if !strings.Contains(result, "Metadata") {
		t.Error("result should contain field 'Metadata'")
	}

	// Should indicate map type
	if !strings.Contains(result, "map") {
		t.Error("result should indicate map type")
	}
}

func TestGenerator_GenerateReference_StructWithPointer(t *testing.T) {
	t.Parallel()

	g := NewGenerator()
	result := g.GenerateReference(structWithPointer{})

	// Should contain pointer field
	if !strings.Contains(result, "Optional") {
		t.Error("result should contain field 'Optional'")
	}

	// Should indicate optional in the output
	if !strings.Contains(result, "optional") {
		t.Error("result should indicate optional field")
	}
}

func TestGenerator_GenerateReference_OnlyPublicFields(t *testing.T) {
	t.Parallel()

	g := NewGenerator()
	result := g.GenerateReference(structWithPrivateFields{})

	// Should contain public field
	if !strings.Contains(result, "Public") {
		t.Error("result should contain field 'Public'")
	}

	// Should NOT contain private field
	if strings.Contains(result, "private") {
		t.Error("result should NOT contain private field 'private'")
	}
}

func TestGenerator_GenerateReference_MarkdownFormat(t *testing.T) {
	t.Parallel()

	g := NewGenerator()
	result := g.GenerateReference(simpleStruct{})

	// Should be valid markdown with table
	if !strings.Contains(result, "|") {
		t.Error("result should contain markdown table delimiter '|'")
	}

	// Should have header row
	if !strings.Contains(result, "Field") {
		t.Error("result should contain 'Field' header")
	}
	if !strings.Contains(result, "Type") {
		t.Error("result should contain 'Type' header")
	}
}

func TestGenerator_GenerateReference_WithPrefix(t *testing.T) {
	t.Parallel()

	g := NewGenerator()
	result := g.GenerateReferenceWithPrefix(simpleStruct{}, "config")

	// Should contain prefixed paths
	if !strings.Contains(result, "config.") {
		t.Error("result should contain prefixed paths like 'config.'")
	}
}

func TestGenerator_GenerateReference_EmptyStruct(t *testing.T) {
	t.Parallel()

	type emptyStruct struct{}

	g := NewGenerator()
	result := g.GenerateReference(emptyStruct{})

	// Should not panic and return something reasonable
	if result == "" {
		t.Error("result should not be empty for empty struct")
	}
}

func TestGenerator_ExtractTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tagValue string
		wantJSON string
		wantYAML string
		wantXML  string
	}{
		{
			name:     "all tags present",
			tagValue: `json:"name" yaml:"name" xml:"name"`,
			wantJSON: "name",
			wantYAML: "name",
			wantXML:  "name",
		},
		{
			name:     "with omitempty",
			tagValue: `json:"name,omitempty" yaml:"name,omitempty"`,
			wantJSON: "name",
			wantYAML: "name",
			wantXML:  "",
		},
		{
			name:     "skip field",
			tagValue: `json:"-"`,
			wantJSON: "-",
			wantYAML: "",
			wantXML:  "",
		},
	}

	g := NewGenerator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tags := g.extractTags(tt.tagValue)

			if tags.JSON != tt.wantJSON {
				t.Errorf("JSON tag = %q, want %q", tags.JSON, tt.wantJSON)
			}
			if tags.YAML != tt.wantYAML {
				t.Errorf("YAML tag = %q, want %q", tags.YAML, tt.wantYAML)
			}
			if tags.XML != tt.wantXML {
				t.Errorf("XML tag = %q, want %q", tags.XML, tt.wantXML)
			}
		})
	}
}
