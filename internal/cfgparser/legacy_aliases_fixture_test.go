package cfgparser

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/sanitizer"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // self-registers OPNsense parser via init()
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParser_OPNsenseLegacyAliasesFixture parses
// testdata/opnsense-legacy-aliases.xml end-to-end through the full XML
// dispatch (this package's XMLParser, not direct struct construction) and
// proves the legacy top-level <aliases> block populates common.NamedObjects.
// Before U3, handleStartElement had no "aliases" case, so this fixture
// converted to namedObjects: null.
func TestParser_OPNsenseLegacyAliasesFixture(t *testing.T) {
	t.Parallel()

	device := parseLegacyAliasesFixture(t)

	require.Len(t, device.NamedObjects, 2)

	legacyHosts, ok := device.NamedObjects["LEGACY_HOSTS"]
	require.True(t, ok)
	assert.Equal(t, common.NamedObjectTypeHost, legacyHosts.Type)
	assert.Equal(t, []string{"10.5.5.1", "10.5.5.2"}, legacyHosts.Members)

	legacySecret, ok := device.NamedObjects["LEGACY_SECRET"]
	require.True(t, ok)
	assert.Equal(t, []string{"10.5.5.3"}, legacySecret.Members)
}

// legacySecretMarker is the secret-shaped value embedded in
// testdata/opnsense-legacy-aliases.xml's LEGACY_SECRET alias description: a
// base64-encoded opaque blob (no field-name pattern like "descr" matches any
// redaction rule by name) that the sanitizer's certificate/public-key
// value-detector rules catch regardless of field name in aggressive mode.
// It deliberately contains no whitespace, so the sanitizer's per-token value
// detection -- which splits a CharData leaf on whitespace before running any
// ValueDetector, see internal/sanitizer.replaceTokens -- sees it as a single
// token.
// secret-*shaped* so the redaction assertion below has something to detect.
//
//nolint:gosec // G101: not a credential -- a base64 test marker whose only job is to be
const legacySecretMarker = "c3VwZXItc2VjcmV0LWxlZ2FjeS1hbGlhcy1hcGkta2V5LTAxMjM0NTY3ODk="

// TestParser_OPNsenseLegacyAliasesFixture_SecretRedacted proves the legacy
// top-level <aliases> path -- unreachable before U3 -- is covered by the
// sanitizer's redaction rules like any other config path: the secret-shaped
// alias description in testdata/opnsense-legacy-aliases.xml never survives
// sanitize-then-convert, whether inspected as JSON output or as the parsed
// NamedObjects.Description value directly.
func TestParser_OPNsenseLegacyAliasesFixture_SecretRedacted(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(legacyAliasesFixturePath())
	require.NoError(t, err)
	require.Contains(t, string(raw), legacySecretMarker, "fixture must still carry the secret this test redacts")

	var sanitized bytes.Buffer
	san := sanitizer.NewSanitizer(sanitizer.ModeAggressive)
	require.NoError(t, san.SanitizeXML(bytes.NewReader(raw), &sanitized))
	assert.NotContains(t, sanitized.String(), legacySecretMarker, "sanitized XML must not carry the secret in clear")

	factory := parser.NewFactory(NewXMLParser())
	device, _, err := factory.CreateDevice(context.Background(), &sanitized, common.DeviceTypeUnknown, false)
	require.NoError(t, err)
	require.NotNil(t, device)

	legacySecret, ok := device.NamedObjects["LEGACY_SECRET"]
	require.True(t, ok)
	assert.NotContains(t, legacySecret.Description, legacySecretMarker)

	jsonOut, err := json.Marshal(device)
	require.NoError(t, err)
	assert.NotContains(t, string(jsonOut), legacySecretMarker, "secret must not survive into JSON export")
}

// legacyAliasesFixturePath returns the path to
// testdata/opnsense-legacy-aliases.xml relative to this test's working
// directory (the package directory, per Go test convention).
func legacyAliasesFixturePath() string {
	return filepath.Join("..", "..", "testdata", "opnsense-legacy-aliases.xml")
}

// parseLegacyAliasesFixture opens and parses
// testdata/opnsense-legacy-aliases.xml through the full parser pipeline,
// failing the test on any error.
func parseLegacyAliasesFixture(t *testing.T) *common.CommonDevice {
	t.Helper()

	f, err := os.Open(legacyAliasesFixturePath())
	require.NoError(t, err)
	defer f.Close()

	factory := parser.NewFactory(NewXMLParser())
	device, warnings, err := factory.CreateDevice(context.Background(), f, common.DeviceTypeUnknown, false)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.NotNil(t, device)

	return device
}
