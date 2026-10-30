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

	config := fmt.Sprintf(`<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  <interfaces><wan><if>vtnet0</if></wan></interfaces>
  <staticroutes%s>%s</staticroutes>
</opnsense>`, attr, body.String())

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

// TestConverter_StaticRoutes_Enabled pins how a route's state is read across
// the OPNsense 26.1.10 change: Routes model 1.0.1 replaced <disabled> with
// <enabled>, and its migration deletes <disabled>. get_staticroutes (util.inc)
// reads <enabled> when present, disabled when empty or 0, and falls back to
// <disabled> only without it. That fallback keeps the BoolFlag reading, which
// agrees with the !empty() the firewall has used since 18.1 on the 0 and 1 the
// model writes, but not on every other value.
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
			name:    "any other value is not empty() and reads as enabled",
			version: "1.0.1",
			routes: []string{
				`<enabled>no</enabled>`, `<enabled>false</enabled>`, `<enabled>off</enabled>`, `<enabled>yes</enabled>`,
			},
			want: []bool{false, false, false, false},
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

	for _, version := range []string{"", "1.0.0", "1.0.1"} {
		_, warnings := parseStaticRoutes(t, version, `<enabled>1</enabled>`)
		assert.Empty(t, warnings, "version %q", version)
	}

	device, warnings := parseStaticRoutes(t, "1.0.2", `<enabled>0</enabled>`)
	require.Len(t, warnings, 1)
	assert.Equal(t, "StaticRoutes.Version", warnings[0].Field)
	assert.Equal(t, "1.0.2", warnings[0].Value)
	assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
	assert.Equal(t, []bool{true}, routesDisabled(device))

	device, warnings = parseStaticRoutes(t, "1.0.2")
	require.Len(t, warnings, 1)
	assert.Equal(t, "StaticRoutes.Version", warnings[0].Field)
	assert.Empty(t, device.Routing.StaticRoutes)
}
