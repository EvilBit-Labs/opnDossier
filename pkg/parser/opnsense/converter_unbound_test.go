package opnsense_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const unboundVersionWarningField = "DNS.Unbound.UnboundPlus.Version"

// parseUnboundXML runs a config holding body under <opnsense> through the real
// parser and converter. The bug these tests guard against is in which store a
// setting is read from, which only decoded XML shows.
func parseUnboundXML(t *testing.T, body string) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	doc := `<?xml version="1.0"?><opnsense>` + body + `</opnsense>`
	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(
		context.Background(), strings.NewReader(doc), common.DeviceTypeUnknown, false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)

	return device, warnings
}

// unboundPlus wraps general and advanced children in the model at version.
func unboundPlus(version, general, advanced string) string {
	return `<OPNsense><unboundplus version="` + version + `"><general>` + general +
		`</general><advanced>` + advanced + `</advanced></unboundplus></OPNsense>`
}

// TestConverter_Unbound_ServiceFlagsFollowModelVersion pins which store
// Enabled, DNSSEC and DNSSECStripped come from. Migration 1.0.5 (23.7) moves
// enable and dnssec into <general> and 1.0.3 moves dnssecstripped into
// <advanced>; each unsets the legacy key, so a reader of <unbound> alone saw
// Unbound as off on every config written since 23.7.
func TestConverter_Unbound_ServiceFlagsFollowModelVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		body         string
		wantEnabled  bool
		wantDNSSEC   bool
		wantStripped bool
	}{
		{
			name: "26.7 model, all on",
			body: unboundPlus(
				"1.0.15",
				`<enabled>1</enabled><dnssec>1</dnssec>`,
				`<dnssecstripped>1</dnssecstripped>`,
			),
			wantEnabled:  true,
			wantDNSSEC:   true,
			wantStripped: true,
		},
		{
			name: "26.7 model, disabled but validating",
			body: unboundPlus(
				"1.0.15",
				`<enabled>0</enabled><dnssec>1</dnssec>`,
				`<dnssecstripped>0</dnssecstripped>`,
			),
			wantEnabled:  false,
			wantDNSSEC:   true,
			wantStripped: false,
		},
		{
			name:        "23.7 model, enabled without DNSSEC",
			body:        unboundPlus("1.0.6", `<enabled>1</enabled><dnssec/>`, `<dnssecstripped>1</dnssecstripped>`),
			wantEnabled: true, wantStripped: true,
		},
		{
			name: "model elements absent take the defaults",
			body: unboundPlus("1.0.15", `<port>53</port>`, ``),
		},
		{
			name: "a migrated model ignores a stale legacy element",
			body: `<unbound><enable>1</enable><dnssec>1</dnssec><dnssecstripped>1</dnssecstripped></unbound>` +
				unboundPlus("1.0.15", `<enabled>0</enabled><dnssec>0</dnssec>`, `<dnssecstripped>0</dnssecstripped>`),
		},
		{
			name: "23.1 shape reads enable and dnssec from legacy",
			body: `<unbound><enable>1</enable><dnssec>1</dnssec></unbound>` +
				`<OPNsense><unboundplus version="1.0.4"><advanced><dnssecstripped>1</dnssecstripped></advanced></unboundplus></OPNsense>`,
			wantEnabled:  true,
			wantDNSSEC:   true,
			wantStripped: true,
		},
		{
			name: "pre-1.0.3 shape reads all three from legacy",
			body: `<unbound><enable>1</enable><dnssecstripped>1</dnssecstripped></unbound>` +
				`<OPNsense><unboundplus version="1.0.2"><general/></unboundplus></OPNsense>`,
			wantEnabled:  true,
			wantStripped: true,
		},
		{
			name:        "1.0.5 is the first model to hold enabled",
			body:        unboundPlus("1.0.5", `<enabled>1</enabled>`, ``),
			wantEnabled: true,
		},
		{
			name:         "1.0.3 is the first model to hold dnssecstripped",
			body:         unboundPlus("1.0.3", ``, `<dnssecstripped>1</dnssecstripped>`),
			wantStripped: true,
		},
		{
			// The firewall reads only the model from 1.0.5 on, so the stale
			// legacy element counts for nothing and the model default applies.
			name: "1.0.15 without enabled ignores a stale legacy enable",
			body: `<unbound><enable>1</enable></unbound>` + unboundPlus("1.0.15", `<port>53</port>`, ``),
		},
		{
			name: "1.0.4 legacy elements count whatever they hold",
			body: `<unbound><enable>on</enable><dnssec>yes</dnssec></unbound>` +
				unboundPlus("1.0.4", ``, ``),
			wantEnabled: true,
			wantDNSSEC:  true,
		},
		{
			name: "a later minor version reads the model",
			body: `<unbound><enable>1</enable><dnssec>1</dnssec></unbound>` +
				unboundPlus("1.1.0", `<enabled>0</enabled><dnssec>1</dnssec>`, ``),
			wantDNSSEC: true,
		},
		{
			name:        "no version attribute reads the model when it holds the value",
			body:        `<OPNsense><unboundplus><general><enabled>1</enabled><dnssec>1</dnssec></general></unboundplus></OPNsense>`,
			wantEnabled: true,
			wantDNSSEC:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device, _ := parseUnboundXML(t, tc.body)
			got := device.DNS.Unbound
			assert.Equal(t, tc.wantEnabled, got.Enabled, "Enabled")
			assert.Equal(t, tc.wantDNSSEC, got.DNSSEC, "DNSSEC")
			assert.Equal(t, tc.wantStripped, got.DNSSECStripped, "DNSSECStripped")
		})
	}
}

// TestConverter_Unbound_KnownModelVersions checks that every model version
// from 1.0.0 to 26.7's 1.0.15 converts without a warning, that the accepted set
// holds nothing else, and that a later version still warns.
func TestConverter_Unbound_KnownModelVersions(t *testing.T) {
	t.Parallel()

	const lastCheckedPatch = 15

	want := map[string]struct{}{"": {}}
	for patch := 0; patch <= lastCheckedPatch; patch++ {
		version := fmt.Sprintf("1.0.%d", patch)
		want[version] = struct{}{}

		_, warnings := parseUnboundXML(t, unboundPlus(version, `<enabled>1</enabled>`, ``))
		assert.Nil(t, findWarning(warnings, unboundVersionWarningField, version), "version %s", version)
	}

	assert.Equal(t, want, opnsense.KnownUnboundPlusVersions)

	_, warnings := parseUnboundXML(t, unboundPlus("1.0.16", `<enabled>1</enabled>`, ``))
	assert.NotNil(t, findWarning(warnings, unboundVersionWarningField, "1.0.16"))
}

// TestConverter_Unbound_SampleConfig5 reads the one shipped fixture with a
// migrated model: unboundplus 1.0.9 with <enabled>1</enabled> and <dnssec/>.
func TestConverter_Unbound_SampleConfig5(t *testing.T) {
	t.Parallel()

	file, err := os.Open(filepath.Join("..", "..", "..", "testdata", "sample.config.5.xml"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(context.Background(), file, common.DeviceTypeUnknown, false)
	require.NoError(t, err)

	assert.True(t, device.DNS.Unbound.Enabled)
	assert.False(t, device.DNS.Unbound.DNSSEC)
	assert.Nil(t, findWarning(warnings, unboundVersionWarningField, "1.0.9"))
}
