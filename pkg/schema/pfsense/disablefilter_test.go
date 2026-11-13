package pfsense

import (
	"encoding/xml"
	"strings"
	"testing"
)

// TestSystem_DisableFilterRoundTrip pins the presence semantics of
// <disablefilter> (standards.md "Adding New XML Fields" step 3). The firewall
// tests the element with isset(), so an empty element disables filtering as the
// page's "enabled" does: an absent element must decode to nil and stay absent,
// and a present one must keep its body through a round trip.
func TestSystem_DisableFilterRoundTrip(t *testing.T) {
	t.Parallel()

	empty, enabled := "", "enabled"

	tests := []struct {
		name string
		in   string
		want *string
	}{
		{name: "absent", in: "<system></system>"},
		{name: "empty element", in: "<system><disablefilter/></system>", want: &empty},
		{name: "page value", in: "<system><disablefilter>enabled</disablefilter></system>", want: &enabled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var sys System
			if err := xml.Unmarshal([]byte(tt.in), &sys); err != nil {
				t.Fatal(err)
			}

			switch {
			case tt.want == nil && sys.DisableFilter != nil:
				t.Fatalf("DisableFilter = %q, want nil", *sys.DisableFilter)
			case tt.want != nil && (sys.DisableFilter == nil || *sys.DisableFilter != *tt.want):
				t.Fatalf("DisableFilter = %v, want %q", sys.DisableFilter, *tt.want)
			}

			out, err := xml.Marshal(&sys)
			if err != nil {
				t.Fatal(err)
			}

			var again System
			if err := xml.Unmarshal(out, &again); err != nil {
				t.Fatal(err)
			}

			if (again.DisableFilter == nil) != (tt.want == nil) ||
				(tt.want != nil && *again.DisableFilter != *tt.want) {
				t.Errorf("round trip changed DisableFilter: %s", out)
			}

			if tt.want == nil && strings.Contains(string(out), "disablefilter") {
				t.Errorf("absent element written back: %s", out)
			}
		})
	}
}
