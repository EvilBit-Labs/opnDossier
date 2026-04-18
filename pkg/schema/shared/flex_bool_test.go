package shared_test

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/schema/shared"
	"gopkg.in/yaml.v3"
)

type flexWrap struct {
	XMLName xml.Name        `xml:"wrap" json:"-"   yaml:"-"`
	Val     shared.FlexBool `xml:"val"  json:"val" yaml:"val"`
}

func TestFlexBool_UnmarshalXML(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
		want bool
	}{
		{"on lowercase", "on", true},
		{"ON uppercase", "ON", true},
		{"yes", "yes", true},
		{"true", "true", true},
		{"one", "1", true},
		{"enabled", "enabled", true},
		{"enable", "enable", true},
		{"off", "off", false},
		{"no", "no", false},
		{"false", "false", false},
		{"zero", "0", false},
		{"disabled", "disabled", false},
		{"empty", "", false},
		{"whitespace yes", "  yes  ", true},
		{"unknown banana", "banana", false},
		{"unknown 2", "2", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			xmlDoc := "<wrap><val>" + tc.body + "</val></wrap>"
			var w flexWrap
			if err := xml.Unmarshal([]byte(xmlDoc), &w); err != nil {
				t.Fatalf("xml.Unmarshal(%q): %v", xmlDoc, err)
			}
			if got := w.Val.Bool(); got != tc.want {
				t.Errorf("FlexBool(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestFlexBool_UnmarshalXML_SelfClosing(t *testing.T) {
	t.Parallel()

	// <val/> -- empty body -- is falsy (empty string matches IsValueFalse).
	// Callers who want presence = true should use BoolFlag instead.
	var w flexWrap
	if err := xml.Unmarshal([]byte("<wrap><val/></wrap>"), &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if w.Val.Bool() != false {
		t.Errorf("FlexBool(<val/>) = %v, want false", w.Val.Bool())
	}
}

func TestFlexBool_MarshalXML(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		val  bool
		want string
	}{
		{"true", true, "<wrap><val>1</val></wrap>"},
		{"false", false, "<wrap><val>0</val></wrap>"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Marshal by pointer to satisfy pointer-receiver MarshalXML
			// (see GOTCHAS §15.1 for the addressability pattern).
			var buf strings.Builder
			enc := xml.NewEncoder(&buf)
			w := &flexWrap{Val: shared.FlexBool(tc.val)}
			if err := enc.Encode(w); err != nil {
				t.Fatalf("encode: %v", err)
			}
			if got := buf.String(); got != tc.want {
				t.Errorf("marshal %v = %q, want %q", tc.val, got, tc.want)
			}
		})
	}
}

func TestFlexBool_JSON(t *testing.T) {
	t.Parallel()

	// MarshalJSON emits native bool.
	out, err := json.Marshal(shared.FlexBool(true))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != "true" {
		t.Errorf("MarshalJSON(true) = %s, want true", out)
	}

	// UnmarshalJSON accepts native bool literals.
	var fb shared.FlexBool
	if err := json.Unmarshal([]byte("true"), &fb); err != nil {
		t.Fatalf("unmarshal true: %v", err)
	}
	if !fb.Bool() {
		t.Errorf("unmarshal true = false")
	}

	// UnmarshalJSON also accepts string forms.
	if err := json.Unmarshal([]byte(`"on"`), &fb); err != nil {
		t.Fatalf("unmarshal \"on\": %v", err)
	}
	if !fb.Bool() {
		t.Errorf("unmarshal \"on\" = false")
	}
}

// TestFlexBool_UnmarshalJSON_EscapeSequences verifies that JSON string
// escapes are decoded before being compared against the truthy vocabulary.
// Prior implementations hand-stripped surrounding quotes without unescaping,
// so "\u006fn" (legal JSON for "on") silently parsed as false.
func TestFlexBool_UnmarshalJSON_EscapeSequences(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		data string
		want bool
	}{
		{"escaped on via unicode", `"\u006fn"`, true},
		{"escaped yes via unicode", `"\u0079es"`, true},
		{"escaped off via unicode", `"\u006fff"`, false},
		{"string true", `"true"`, true},
		{"string false", `"false"`, false},
		{"native true", `true`, true},
		{"native false", `false`, false},
		{"native one", `1`, true},
		{"native zero", `0`, false},
		{"native number non-zero", `42`, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var fb shared.FlexBool
			if err := json.Unmarshal([]byte(tc.data), &fb); err != nil {
				t.Fatalf("unmarshal %s: %v", tc.data, err)
			}
			if got := fb.Bool(); got != tc.want {
				t.Errorf("FlexBool(%s) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}

func TestFlexBool_YAML(t *testing.T) {
	t.Parallel()

	// MarshalYAML emits native bool.
	out, err := yaml.Marshal(shared.FlexBool(true))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// yaml.v3 emits "true" with a trailing newline
	if strings.TrimSpace(string(out)) != "true" {
		t.Errorf("MarshalYAML(true) = %q, want true", out)
	}

	// yaml.v3 routes "on" through UnmarshalYAML's node.Value — IsValueTrue handles it.
	var fb shared.FlexBool
	if err := yaml.Unmarshal([]byte("\"on\"\n"), &fb); err != nil {
		t.Fatalf("unmarshal \"on\": %v", err)
	}
	if !fb.Bool() {
		t.Errorf("unmarshal \"on\" = false")
	}
}
