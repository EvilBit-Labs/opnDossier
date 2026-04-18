package shared_test

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/schema/shared"
	"gopkg.in/yaml.v3"
)

type flexIntWrap struct {
	XMLName xml.Name       `xml:"wrap"`
	Val     shared.FlexInt `xml:"val"`
}

func TestFlexInt_UnmarshalXML(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		body    string
		want    int
		wantErr bool
	}{
		{"numeric positive", "42", 42, false},
		{"numeric zero", "0", 0, false},
		{"numeric negative", "-1", -1, false},
		{"truthy on", "on", 1, false},
		{"truthy yes", "yes", 1, false},
		{"truthy true", "true", 1, false},
		{"truthy enabled", "enabled", 1, false},
		{"falsy off", "off", 0, false},
		{"falsy no", "no", 0, false},
		{"falsy empty", "", 0, false},
		{"truthy whitespace", "  on  ", 1, false},
		{"unknown banana", "banana", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var w flexIntWrap
			err := xml.Unmarshal([]byte("<wrap><val>"+tc.body+"</val></wrap>"), &w)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got none (value=%d)", tc.body, w.Val.Int())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := w.Val.Int(); got != tc.want {
				t.Errorf("FlexInt(%q) = %d, want %d", tc.body, got, tc.want)
			}
		})
	}
}

func TestFlexInt_MarshalXML(t *testing.T) {
	t.Parallel()

	var buf strings.Builder
	enc := xml.NewEncoder(&buf)
	w := &flexIntWrap{Val: shared.FlexInt(42)}
	if err := enc.Encode(w); err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := "<wrap><val>42</val></wrap>"
	if got := buf.String(); got != want {
		t.Errorf("marshal = %q, want %q", got, want)
	}
}

func TestFlexInt_JSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		data    string
		want    int
		wantErr bool
	}{
		{"native int positive", `42`, 42, false},
		{"native int zero", `0`, 0, false},
		{"native int negative", `-1`, -1, false},
		{"native bool true", `true`, 1, false},
		{"native bool false", `false`, 0, false},
		{"string on", `"on"`, 1, false},
		{"string off", `"off"`, 0, false},
		{"string numeric", `"42"`, 42, false},
		{"string unknown errors", `"banana"`, 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var fi shared.FlexInt
			err := json.Unmarshal([]byte(tc.data), &fi)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s, got none", tc.data)
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal %s: %v", tc.data, err)
			}
			if got := fi.Int(); got != tc.want {
				t.Errorf("FlexInt(%s) = %d, want %d", tc.data, got, tc.want)
			}
		})
	}

	// MarshalJSON emits canonical integer.
	out, err := json.Marshal(shared.FlexInt(42))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != "42" {
		t.Errorf("MarshalJSON(42) = %s, want 42", out)
	}
}

func TestFlexInt_YAML(t *testing.T) {
	t.Parallel()

	// MarshalYAML emits native YAML integer.
	out, err := yaml.Marshal(shared.FlexInt(42))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.TrimSpace(string(out)) != "42" {
		t.Errorf("MarshalYAML(42) = %q, want 42", out)
	}

	// Unmarshal native integer node.
	var fi shared.FlexInt
	if err := yaml.Unmarshal([]byte("42\n"), &fi); err != nil {
		t.Fatalf("unmarshal 42: %v", err)
	}
	if fi.Int() != 42 {
		t.Errorf("unmarshal 42 = %d, want 42", fi.Int())
	}

	// Unmarshal truthy string.
	if err := yaml.Unmarshal([]byte("\"on\"\n"), &fi); err != nil {
		t.Fatalf("unmarshal \"on\": %v", err)
	}
	if fi.Int() != 1 {
		t.Errorf("unmarshal \"on\" = %d, want 1", fi.Int())
	}

	// Native YAML integer forms that strconv.Atoi can't parse directly.
	// yaml.v3 decodes these natively via node.Decode(&int) — the branch on
	// node.Tag == "!!int" must be in place to preserve them.
	nativeForms := []struct {
		name string
		yaml string
		want int
	}{
		{"hex 0x10", "0x10\n", 16},
		{"octal 0o20", "0o20\n", 16},
		{"underscored 1_000", "1_000\n", 1000},
		{"negative -5", "-5\n", -5},
	}
	for _, tc := range nativeForms {
		var nfi shared.FlexInt
		if err := yaml.Unmarshal([]byte(tc.yaml), &nfi); err != nil {
			t.Errorf("unmarshal %s: %v", tc.name, err)

			continue
		}
		if nfi.Int() != tc.want {
			t.Errorf("unmarshal %s = %d, want %d", tc.name, nfi.Int(), tc.want)
		}
	}

	// Native YAML bool coerces to 0/1.
	var tfi shared.FlexInt
	if err := yaml.Unmarshal([]byte("true\n"), &tfi); err != nil {
		t.Fatalf("unmarshal native bool true: %v", err)
	}
	if tfi.Int() != 1 {
		t.Errorf("unmarshal true = %d, want 1", tfi.Int())
	}
}
