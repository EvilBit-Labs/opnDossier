package pfsense

import "testing"

// TestFilterRule_Quick_XMLRoundTrip pins <quick> on a filter rule (standards.md
// "Adding New XML Fields" step 3). pfSense tests the element with isset()
// (filter.inc L3387), so what it holds has to survive and an empty one must not
// read as an absent one. Every rule here is floating, the only rule the element
// changes.
func TestFilterRule_Quick_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	const (
		neighborAbsent = floatingYes
		neighborSet    = floatingYes + "<quick>yes</quick>"
	)

	tests := []struct {
		name     string
		element  string
		neighbor string
		want     *string
	}{
		{name: "self-closing element", element: floatingYes + "<quick/>", neighbor: neighborAbsent, want: new("")},
		{name: "empty element", element: floatingYes + "<quick></quick>", neighbor: neighborAbsent, want: new("")},
		{name: "element holding yes", element: neighborSet, neighbor: neighborAbsent, want: new("yes")},
		{
			name:     "element holding 0",
			element:  floatingYes + "<quick>0</quick>",
			neighbor: neighborAbsent,
			want:     new("0"),
		},
		{
			name:     "element holding no",
			element:  floatingYes + "<quick>no</quick>",
			neighbor: neighborAbsent,
			want:     new("no"),
		},
		{name: "absent element", element: neighborAbsent, neighbor: neighborSet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assertRuleElementRoundTrip(t, tt.neighbor, tt.element, tt.want, func(rule *FilterRule) *string {
				return rule.Quick
			})
		})
	}
}

// TestFilterRule_Quick_JSON pins the JSON key of the retyped field.
func TestFilterRule_Quick_JSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		rule        FilterRule
		wantPresent bool
		wantValue   any
	}{
		{name: "absent element"},
		{name: "empty element", rule: FilterRule{Quick: new("")}, wantPresent: true, wantValue: ""},
		{name: "element holding 0", rule: FilterRule{Quick: new("0")}, wantPresent: true, wantValue: "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assertRuleJSONKey(t, tt.rule, "quick", tt.wantPresent, tt.wantValue)
		})
	}
}
