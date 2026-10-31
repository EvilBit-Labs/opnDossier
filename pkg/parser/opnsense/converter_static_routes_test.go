package opnsense_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseStaticRoutes runs a config whose <staticroutes> carries version and
// holds the given <route> bodies through the full parser pipeline.
func parseStaticRoutes(
	t *testing.T,
	version string,
	routes ...string,
) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	var body strings.Builder
	for i, route := range routes {
		fmt.Fprintf(&body, `<route uuid="00000000-0000-0000-0000-%012d"><network>10.%d.0.0/16</network>`+
			`<gateway>WAN_GW</gateway><descr>route %d</descr>%s</route>`, i, i, i, route)
	}

	attr := ""
	if version != "" {
		attr = fmt.Sprintf(` version=%q`, version)
	}

	return parseStaticRoutesBlock(t, fmt.Sprintf(`<staticroutes%s>%s</staticroutes>`, attr, body.String()))
}

// parseStaticRoutesBlock runs a config holding block, a whole <staticroutes>
// element, through the full parser pipeline. It serves the shapes
// parseStaticRoutes cannot build, since that wraps every route body in a network
// and a gateway.
func parseStaticRoutesBlock(t *testing.T, block string) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	config := fmt.Sprintf(`<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  <interfaces><wan><if>vtnet0</if></wan></interfaces>
  %s
</opnsense>`, block)

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(
		context.Background(), strings.NewReader(config), common.DeviceTypeUnknown, false)
	require.NoError(t, err)

	return device, warnings
}

// routesDisabled lists each static route's Disabled flag in order.
func routesDisabled(device *common.CommonDevice) []bool {
	disabled := make([]bool, 0, len(device.Routing.StaticRoutes))
	for _, route := range device.Routing.StaticRoutes {
		disabled = append(disabled, route.Disabled)
	}

	return disabled
}

// assertRoutesVersionWarning requires warnings to be the one warning an
// unrecognized Routes model version raises.
func assertRoutesVersionWarning(t *testing.T, warnings []common.ConversionWarning, version string) {
	t.Helper()

	require.Len(t, warnings, 1)
	assert.Equal(t, "StaticRoutes.Version", warnings[0].Field)
	assert.Equal(t, version, warnings[0].Value)
	assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
	assert.Contains(t, warnings[0].Message, "static routes model version")
}

// TestConverter_StaticRoutes_Enabled pins how a route's state is read across
// the OPNsense 26.1.10 change: Routes model 1.0.1 replaced <disabled> with
// <enabled>, and its migration deletes <disabled>. get_staticroutes (util.inc)
// reads <enabled> when present, disabled when empty or 0, and falls back to
// <disabled> only without it. That fallback keeps the BoolFlag reading, which
// agrees with the !empty() the firewall has used since 18.1 on the 0 and 1 the
// model writes, but not on every other value. The element present decides, not
// the model version: get_staticroutes never reads the version.
func TestConverter_StaticRoutes_Enabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		routes  []string
		want    []bool
	}{
		{
			name:    "model 1.0.1",
			version: "1.0.1",
			routes:  []string{`<enabled>1</enabled>`, `<enabled>0</enabled>`, `<enabled/>`},
			want:    []bool{false, true, true},
		},
		{
			// PHP compares the body with "0" as a string and does not trim it, so a
			// padded 0 or a 00 is not empty() either.
			name:    "any other value is not empty() and reads as enabled",
			version: "1.0.1",
			routes: []string{
				`<enabled>no</enabled>`, `<enabled>false</enabled>`, `<enabled>off</enabled>`, `<enabled>yes</enabled>`,
				`<enabled> 0 </enabled>`, `<enabled>00</enabled>`,
			},
			want: []bool{false, false, false, false, false, false},
		},
		{
			name:    "model 1.0.0",
			version: "1.0.0",
			routes:  []string{`<disabled>0</disabled>`, `<disabled>1</disabled>`, ``},
			want:    []bool{false, true, false},
		},
		{
			// Since 18.1 the firewall reads these three the other way, with
			// !empty(). The Routes model writes only 0 and 1 here, so the BoolFlag
			// reading is kept; this row makes changing it a decision.
			name:    "model 1.0.0 keeps the BoolFlag reading of values the model does not write",
			version: "1.0.0",
			routes:  []string{`<disabled/>`, `<disabled>no</disabled>`, `<disabled>false</disabled>`},
			want:    []bool{true, false, false},
		},
		{
			name:    "enabled wins over a leftover disabled",
			version: "1.0.1",
			routes: []string{
				`<disabled>1</disabled><enabled>1</enabled>`,
				`<disabled>0</disabled><enabled>0</enabled>`,
			},
			want: []bool{false, true},
		},
		{
			name:    "enabled decides at model 1.0.0",
			version: "1.0.0",
			routes:  []string{`<enabled>0</enabled>`, `<disabled>1</disabled><enabled>1</enabled>`},
			want:    []bool{true, false},
		},
		{
			name:   "enabled decides with no model version",
			routes: []string{`<enabled>0</enabled>`, `<disabled>1</disabled><enabled>1</enabled>`},
			want:   []bool{true, false},
		},
		{
			name:    "disabled still decides at model 1.0.1 when enabled is absent",
			version: "1.0.1",
			routes:  []string{`<disabled>1</disabled>`, `<disabled>0</disabled>`, ``},
			want:    []bool{true, false, false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseStaticRoutes(t, tc.version, tc.routes...)
			assert.Empty(t, warnings)
			assert.Equal(t, tc.want, routesDisabled(device))
		})
	}
}

// TestConverter_StaticRoutes_UnknownModelVersion warns when <staticroutes>
// carries a Routes model version the converter has not been checked against,
// since a new version can rename or drop the fields read here (GOTCHAS 3.7). A
// renamed <route> decodes to no routes, and the warning is then the only sign
// of it (GOTCHAS 18.1).
func TestConverter_StaticRoutes_UnknownModelVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		version      string
		routes       []string
		wantWarning  bool
		wantDisabled []bool
	}{
		{name: "no version", routes: []string{`<enabled>1</enabled>`}, wantDisabled: []bool{false}},
		{name: "model 1.0.0", version: "1.0.0", routes: []string{`<enabled>1</enabled>`}, wantDisabled: []bool{false}},
		{name: "model 1.0.1", version: "1.0.1", routes: []string{`<enabled>1</enabled>`}, wantDisabled: []bool{false}},
		{
			name:         "unknown version with a route",
			version:      "1.0.2",
			routes:       []string{`<enabled>0</enabled>`},
			wantWarning:  true,
			wantDisabled: []bool{true},
		},
		{
			name:         "unknown version with no routes",
			version:      "1.0.2",
			wantWarning:  true,
			wantDisabled: []bool{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseStaticRoutes(t, tc.version, tc.routes...)
			assert.Equal(t, tc.wantDisabled, routesDisabled(device))

			if !tc.wantWarning {
				assert.Empty(t, warnings)
				return
			}

			assertRoutesVersionWarning(t, warnings, tc.version)
		})
	}
}

// TestConverter_StaticRoutes_UnknownModelVersion_DroppedEntries pins the warning
// on a block whose entries the placeholder guard drops. A firewall with no routes
// writes a <route/> rather than nothing (sample.config.5.xml, GOTCHAS 3.4), and a
// route whose elements a new model version renamed decodes to the same blank
// entry, so it is dropped too and the warning is the only sign of it.
func TestConverter_StaticRoutes_UnknownModelVersion_DroppedEntries(t *testing.T) {
	t.Parallel()

	const version = "1.0.2"

	tests := []struct {
		name         string
		routes       string
		wantDisabled []bool
	}{
		{name: "only a placeholder", routes: `<route/>`, wantDisabled: []bool{}},
		{
			name: "a route whose elements were all renamed",
			routes: `<route uuid="00000000-0000-0000-0000-000000000000">` +
				`<destination>10.0.0.0/16</destination><via>WAN_GW</via></route>`,
			wantDisabled: []bool{},
		},
		{
			name:         "a placeholder after a route",
			routes:       `<route><network>10.0.0.0/16</network><enabled>0</enabled></route><route/>`,
			wantDisabled: []bool{true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseStaticRoutesBlock(t,
				fmt.Sprintf(`<staticroutes version=%q>%s</staticroutes>`, version, tc.routes))
			assert.Equal(t, tc.wantDisabled, routesDisabled(device))
			assertRoutesVersionWarning(t, warnings, version)
		})
	}
}

// TestConverter_StaticRoutes_EnabledAloneIsRetained pins that <enabled> is data
// to the placeholder guard: a hand-written route holding nothing else stays as a
// blank route with the state it carries, and the <route/> beside it is dropped.
func TestConverter_StaticRoutes_EnabledAloneIsRetained(t *testing.T) {
	t.Parallel()

	device, warnings := parseStaticRoutesBlock(t, `<staticroutes version="1.0.1">`+
		`<route><enabled>1</enabled></route><route/><route><enabled>0</enabled></route></staticroutes>`)
	assert.Empty(t, warnings)
	assert.Equal(t, []bool{false, true}, routesDisabled(device))
}
