package opnsense

import (
	"encoding/xml"
	"testing"
)

// TestStaticRoute_IsPlaceholder_ReportsTrueOnlyWhenEveryFieldIsZero covers the
// empty-<route/> guard. OPNsense writes a self-closing placeholder inside
// <staticroutes> when no route is configured, and the predicate must recognize
// it while retaining any entry that carries data -- including one that is only a
// disabled marker.
func TestStaticRoute_IsPlaceholder_ReportsTrueOnlyWhenEveryFieldIsZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		route StaticRoute
		want  bool
	}{
		{name: "zero value is a placeholder", route: StaticRoute{}, want: true},
		{name: "description only is retained", route: StaticRoute{Descr: "to branch office"}, want: false},
		{name: "network only is retained", route: StaticRoute{Network: "10.0.0.0/8"}, want: false},
		{name: "gateway only is retained", route: StaticRoute{Gateway: "WAN_GW"}, want: false},
		{name: "disabled marker alone is retained", route: StaticRoute{Disabled: BoolFlag(true)}, want: false},
		{name: "created timestamp alone is retained", route: StaticRoute{Created: "1700000000"}, want: false},
		{name: "updated timestamp alone is retained", route: StaticRoute{Updated: "1700000000"}, want: false},
		{
			name:  "fully populated is retained",
			route: StaticRoute{Network: "10.0.0.0/8", Gateway: "WAN_GW", Descr: "branch"},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.route.IsPlaceholder(); got != tt.want {
				t.Errorf("IsPlaceholder() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGateway_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder pins, for
// <gateway_item/>, why the predicate compares named fields, and that the
// attribute a model item carries does not make it configured.
func TestGateway_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder(t *testing.T) {
	t.Parallel()

	for _, element := range []string{`<gateway_item/>`, `<gateway_item uuid="7f3c2a1e"></gateway_item>`} {
		var got Gateway
		if err := xml.Unmarshal([]byte(element), &got); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		if got == (Gateway{}) {
			t.Fatal("decoded element equals Gateway{}; the XMLName premise for IsPlaceholder no longer holds")
		}

		if !got.IsPlaceholder() {
			t.Errorf("decoded %s must be reported as a placeholder", element)
		}
	}
}

// TestGateway_MonitorDisable_KeepsAbsentApartFromEmpty pins the distinction the
// field is a pointer for, and the text MonitorDisableValue reads from each.
func TestGateway_MonitorDisable_KeepsAbsentApartFromEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		element   string
		wantIsNil bool
		wantValue string
	}{
		{name: "absent", element: `<gateway_item><name>GW</name></gateway_item>`, wantIsNil: true},
		{name: "self-closing", element: `<gateway_item><monitor_disable/></gateway_item>`},
		{name: "empty", element: `<gateway_item><monitor_disable></monitor_disable></gateway_item>`},
		{
			name:      "set",
			element:   `<gateway_item><monitor_disable>1</monitor_disable></gateway_item>`,
			wantValue: "1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got Gateway
			if err := xml.Unmarshal([]byte(tt.element), &got); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			if isNil := got.MonitorDisable == nil; isNil != tt.wantIsNil {
				t.Errorf("MonitorDisable == nil is %v, want %v", isNil, tt.wantIsNil)
			}

			if value := got.MonitorDisableValue(); value != tt.wantValue {
				t.Errorf("MonitorDisableValue() = %q, want %q", value, tt.wantValue)
			}
		})
	}
}

// TestStaticRoute_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder pins the
// reason the predicate compares named fields instead of the zero value:
// encoding/xml populates XMLName on unmarshal, so a decoded <route/> is never
// equal to StaticRoute{}.
func TestStaticRoute_IsPlaceholder_DecodedEmptyElement_ReportsPlaceholder(t *testing.T) {
	t.Parallel()

	var got StaticRoute
	if err := xml.Unmarshal([]byte(`<route/>`), &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if got == (StaticRoute{}) {
		t.Fatal("decoded <route/> equals StaticRoute{}; the XMLName premise for IsPlaceholder no longer holds")
	}

	if !got.IsPlaceholder() {
		t.Error("decoded <route/> must be reported as a placeholder")
	}
}
