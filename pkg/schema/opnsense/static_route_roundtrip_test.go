package opnsense

import (
	"encoding/xml"
	"reflect"
	"strings"
	"testing"
)

// modelRoutes wraps element in a <staticroutes> block as Routes model 1.0.1
// writes one: a version on the container, a uuid on the route, then network,
// gateway and descr ahead of the element under test.
func modelRoutes(element string) string {
	return `<staticroutes version="1.0.1"><route uuid="8a7c1f52-3b1e-4d6a-9c0f-2e5d7b9a1c34">` +
		`<network>10.20.0.0/16</network><gateway>WAN_GW</gateway><descr>branch office</descr>` +
		element + `</route></staticroutes>`
}

// roundTripStaticRoutes decodes raw, marshals the result and decodes that
// again, failing the test if the second decode differs from the first. It
// returns the first decode and the marshaled text for the caller to check
// against the vendor's spelling: a renamed tag survives a round trip through
// its own output, so equality alone cannot catch one.
//
//nolint:gocritic // unnamedResult retained; project-wide nonamedreturns disables the typical fix.
func roundTripStaticRoutes(t *testing.T, raw string) (StaticRoutes, string) {
	t.Helper()

	var decoded StaticRoutes
	if err := xml.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}

	data, err := xml.Marshal(&decoded)
	if err != nil {
		t.Fatalf("marshal %s: %v", raw, err)
	}

	var back StaticRoutes
	if err := xml.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal after marshal %s: %v", data, err)
	}
	if !reflect.DeepEqual(decoded, back) {
		t.Errorf("round trip changed the routes:\nfrom %s\n  to %s", raw, data)
	}

	return decoded, string(data)
}

// roundTripModelRoute round-trips modelRoutes(element) and returns its one
// route with the marshaled text.
//
//nolint:gocritic // unnamedResult retained; project-wide nonamedreturns disables the typical fix.
func roundTripModelRoute(t *testing.T, element string) (StaticRoute, string) {
	t.Helper()

	routes, out := roundTripStaticRoutes(t, modelRoutes(element))
	if len(routes.Route) != 1 {
		t.Fatalf("%q: got %d routes, want 1", element, len(routes.Route))
	}

	return routes.Route[0], out
}

// TestStaticRoutes_VersionRoundTrip pins the version attribute (standards.md
// "Adding New XML Fields" step 3). The converter warns on a model version it has
// not been checked against, so the attribute must stay on the container, and a
// block without one, as pfSense writes, must not gain an empty attribute.
func TestStaticRoutes_VersionRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		raw      string
		want     string
		wantOpen string
	}{
		{
			name:     "Routes model 1.0.1",
			raw:      modelRoutes(`<enabled>1</enabled>`),
			want:     "1.0.1",
			wantOpen: `<staticroutes version="1.0.1">`,
		},
		{
			name:     "Routes model 1.0.0 holding only a placeholder",
			raw:      `<staticroutes version="1.0.0"><route/></staticroutes>`,
			want:     "1.0.0",
			wantOpen: `<staticroutes version="1.0.0">`,
		},
		{
			name: "pfSense writes no version",
			raw: `<staticroutes><route><network>10.10.0.0/16</network><gateway>GW_WAN</gateway>` +
				`<descr>Remote office route</descr></route></staticroutes>`,
			wantOpen: `<staticroutes>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			routes, out := roundTripStaticRoutes(t, tt.raw)
			if routes.Version != tt.want {
				t.Errorf("Version = %q, want %q", routes.Version, tt.want)
			}
			if !strings.HasPrefix(out, tt.wantOpen) {
				t.Errorf("marshaled %s, want it to open with %s", out, tt.wantOpen)
			}
		})
	}
}

// TestStaticRoute_EnabledRoundTrip pins the presence semantics of <enabled>
// (GOTCHAS 3.2). An absent element leaves the decision to <disabled> and an
// empty one disables the route, so the two must stay apart through a round trip;
// only the nil pointer tells them apart. The model writes 0 or 1. The empty
// forms are what the firewall reads as disabled when a config carries one.
func TestStaticRoute_EnabledRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		element  string
		present  bool
		body     string
		disabled bool
	}{
		{name: "absent, as Routes model 1.0.0 leaves it"},
		{name: "self-closing", element: `<enabled/>`, present: true},
		{name: "empty", element: `<enabled></enabled>`, present: true},
		{name: "off", element: `<enabled>0</enabled>`, present: true, body: "0"},
		{name: "on", element: `<enabled>1</enabled>`, present: true, body: "1"},
		{
			name:     "beside a leftover disabled",
			element:  `<disabled>1</disabled><enabled>1</enabled>`,
			present:  true,
			body:     "1",
			disabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route, out := roundTripModelRoute(t, tt.element)
			if (route.Enabled != nil) != tt.present {
				t.Fatalf("Enabled non-nil = %v, want %v", route.Enabled != nil, tt.present)
			}
			if tt.present && *route.Enabled != tt.body {
				t.Errorf("Enabled = %q, want %q", *route.Enabled, tt.body)
			}
			if bool(route.Disabled) != tt.disabled {
				t.Errorf("Disabled = %v, want %v", route.Disabled, tt.disabled)
			}

			if strings.Contains(out, "<enabled") != tt.present {
				t.Errorf("marshaled element present = %v, want %v: %s", !tt.present, tt.present, out)
			}
			if tt.present && !strings.Contains(out, "<enabled>"+tt.body+"</enabled>") {
				t.Errorf("body %q not preserved: %s", tt.body, out)
			}
		})
	}
}

// TestStaticRoute_IsPlaceholder_EnabledAloneIsRetained pins that <enabled> counts
// by being there, not by what it holds: only a route with no configuration field
// set is the empty marker. The shared every-field test tries only an empty value,
// so it cannot see a guard that treats 0 or 1 as absent.
func TestStaticRoute_IsPlaceholder_EnabledAloneIsRetained(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{name: "self-closing", raw: `<route><enabled/></route>`},
		{name: "off", raw: `<route><enabled>0</enabled></route>`},
		{name: "on", raw: `<route><enabled>1</enabled></route>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var route StaticRoute
			if err := xml.Unmarshal([]byte(tt.raw), &route); err != nil {
				t.Fatalf("unmarshal %s: %v", tt.raw, err)
			}
			if route.IsPlaceholder() {
				t.Errorf("%s must not be reported as a placeholder", tt.raw)
			}
		})
	}
}

// TestStaticRoutes_DisabledRoundTrip_ByValueAndPointer pins the BoolFlag beside
// <enabled> against the pointer-receiver trap (GOTCHAS 15.1). Its MarshalXML is
// only found on an addressable value. A route in the slice always is one, so the
// container marshals alike by value and by pointer.
func TestStaticRoutes_DisabledRoundTrip_ByValueAndPointer(t *testing.T) {
	t.Parallel()

	// Routes model 1.0.0 writes 0 or 1. A BoolFlag has no way to write a false,
	// so the 0 leaves the output and reads the same for it.
	const raw = `<staticroutes version="1.0.0">` +
		`<route><network>10.20.0.0/16</network><gateway>WAN_GW</gateway><disabled>1</disabled></route>` +
		`<route><network>10.30.0.0/16</network><gateway>WAN_GW</gateway><disabled>0</disabled></route>` +
		`</staticroutes>`

	routes, byPointer := roundTripStaticRoutes(t, raw)
	if len(routes.Route) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes.Route))
	}
	if !routes.Route[0].Disabled || routes.Route[1].Disabled {
		t.Errorf("Disabled = %v, %v, want true, false", routes.Route[0].Disabled, routes.Route[1].Disabled)
	}
	// The empty form is pfSense's. OPNsense writes 1, and since 18.1 reads an empty
	// <disabled> as not disabled, so this is not a faithful OPNsense round trip.
	if strings.Count(byPointer, "<disabled>") != 1 || !strings.Contains(byPointer, "<disabled></disabled>") {
		t.Errorf("want one empty <disabled>: %s", byPointer)
	}

	byValue, err := xml.Marshal(routes)
	if err != nil {
		t.Fatalf("marshal by value: %v", err)
	}
	if string(byValue) != byPointer {
		t.Errorf("by value differs from by pointer:\n%s\n%s", byValue, byPointer)
	}

	// A lone route passed by value is not addressable and falls back to the
	// bool's text. That form is not the vendor's, but it must still read back as
	// disabled.
	lone, err := xml.Marshal(routes.Route[0])
	if err != nil {
		t.Fatalf("marshal lone route: %v", err)
	}
	var back StaticRoute
	if err := xml.Unmarshal(lone, &back); err != nil {
		t.Fatalf("unmarshal lone route %s: %v", lone, err)
	}
	if !back.Disabled {
		t.Errorf("lone route read back as not disabled: %s", lone)
	}
}

// TestStaticRoute_CreatedUpdatedRoundTrip pins <created> and <updated> on a
// route. The Routes model defines neither and the legacy route editors set
// neither, so these rows use the scalar body the string fields bind, not a
// shape copied from a config. The <created> block on a firewall rule, with its
// username, time and description children, is a different shape that these
// fields cannot hold.
func TestStaticRoute_CreatedUpdatedRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		element string
		created string
		updated string
	}{
		{
			name:    "both",
			element: `<created>1700000000</created><updated>1700000100</updated>`,
			created: "1700000000",
			updated: "1700000100",
		},
		{name: "created only", element: `<created>1700000000</created>`, created: "1700000000"},
		{name: "updated only", element: `<updated>1700000100</updated>`, updated: "1700000100"},
		{name: "neither"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route, out := roundTripModelRoute(t, tt.element)
			if route.Created != tt.created {
				t.Errorf("Created = %q, want %q", route.Created, tt.created)
			}
			if route.Updated != tt.updated {
				t.Errorf("Updated = %q, want %q", route.Updated, tt.updated)
			}

			if strings.Contains(out, "<created") != (tt.created != "") {
				t.Errorf("<created> presence wrong for %q: %s", tt.created, out)
			}
			if strings.Contains(out, "<updated") != (tt.updated != "") {
				t.Errorf("<updated> presence wrong for %q: %s", tt.updated, out)
			}
			if !strings.Contains(out, tt.element) {
				t.Errorf("elements %s not written back: %s", tt.element, out)
			}
		})
	}
}

// assertDocumentKeepsStaticRoutes marshals doc and decodes the output, failing
// the test if the <staticroutes> block comes back different.
func assertDocumentKeepsStaticRoutes(t *testing.T, doc *OpnSenseDocument) {
	t.Helper()

	data, err := xml.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var back OpnSenseDocument
	if err := xml.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal after marshal: %v", err)
	}
	if !reflect.DeepEqual(doc.StaticRoutes, back.StaticRoutes) {
		t.Errorf("document round trip changed <staticroutes>: %s", data)
	}
}

// TestOpnSenseDocument_StaticRoutesRoundTrip carries the block through the
// document that embeds it. sample.config.5.xml is the one fixture with a version
// on <staticroutes>, so it pins the attribute against a config the vendor wrote.
// No fixture has reached Routes model 1.0.1, so that shape comes from modelRoutes.
func TestOpnSenseDocument_StaticRoutesRoundTrip(t *testing.T) {
	t.Parallel()

	fixture := decodePortForwardFixture(t, "sample.config.5.xml")
	if fixture.StaticRoutes.Version != "1.0.0" {
		t.Errorf("fixture Version = %q, want 1.0.0", fixture.StaticRoutes.Version)
	}
	if len(fixture.StaticRoutes.Route) != 1 || !fixture.StaticRoutes.Route[0].IsPlaceholder() {
		t.Errorf("fixture routes = %d, want one placeholder", len(fixture.StaticRoutes.Route))
	}
	assertDocumentKeepsStaticRoutes(t, &fixture)

	const off = `<enabled>0</enabled>`
	var migrated OpnSenseDocument
	if err := xml.Unmarshal([]byte("<opnsense>"+modelRoutes(off)+"</opnsense>"), &migrated); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if migrated.StaticRoutes.Version != "1.0.1" {
		t.Errorf("migrated Version = %q, want 1.0.1", migrated.StaticRoutes.Version)
	}
	if len(migrated.StaticRoutes.Route) != 1 || migrated.StaticRoutes.Route[0].Enabled == nil {
		t.Fatalf("migrated route lost <enabled>: %+v", migrated.StaticRoutes.Route)
	}
	assertDocumentKeepsStaticRoutes(t, &migrated)
}
