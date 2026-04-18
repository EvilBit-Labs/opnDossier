package shared_test

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/schema/shared"
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
