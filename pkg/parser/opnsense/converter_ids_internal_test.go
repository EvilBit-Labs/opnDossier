package opnsense

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// idsDivertDocument decodes a config in divert mode holding the given rules of the
// filter model.
func idsDivertDocument(t *testing.T, rules string) *schema.OpnSenseDocument {
	t.Helper()

	config := `<opnsense><OPNsense>` +
		`<Firewall><Filter version="1.0.6"><rules>` + rules + `</rules></Filter></Firewall>` +
		`<IDS version="1.1.2"><general><enabled>1</enabled><mode>divert</mode></general></IDS>` +
		`</OPNsense></opnsense>`

	doc, err := cfgparser.NewXMLParser().Parse(context.Background(), strings.NewReader(config))
	require.NoError(t, err)

	return doc
}

// TestConverter_IDSDivertRule_DoesNotCarryOver reuses one converter, as
// ToCommonDevice allows by resetting its warnings, and pins that the rule found in
// one document does not stand in for a rule missing from the next.
func TestConverter_IDSDivertRule_DoesNotCarryOver(t *testing.T) {
	t.Parallel()

	c := newConverter()

	device, _, err := c.ToCommonDevice(idsDivertDocument(t, `<rule><divert-to>8000</divert-to></rule>`))
	require.NoError(t, err)
	assert.True(t, device.IDS.IPSMode)

	device, _, err = c.ToCommonDevice(idsDivertDocument(t, ""))
	require.NoError(t, err)
	assert.False(t, device.IDS.IPSMode)
}
