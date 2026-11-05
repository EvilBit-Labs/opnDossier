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

// TestConverter_ConvertFirewallRules_ReportsDivertRule pins the second result of
// convertFirewallRules, which convertIDs reads to settle divert mode: set by an
// enabled pass rule with divert-to 8000, and by nothing else.
func TestConverter_ConvertFirewallRules_ReportsDivertRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rules string
		want  bool
	}{
		{name: "no rules", rules: "", want: false},
		{name: "pass rule to Suricata", rules: `<rule><divert-to>8000</divert-to></rule>`, want: true},
		{name: "disabled rule", rules: `<rule><enabled>0</enabled><divert-to>8000</divert-to></rule>`, want: false},
		{name: "block rule", rules: `<rule><action>block</action><divert-to>8000</divert-to></rule>`, want: false},
		{name: "other divert port", rules: `<rule><divert-to>8001</divert-to></rule>`, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, got := newConverter().convertFirewallRules(idsDivertDocument(t, tc.rules))
			assert.Equal(t, tc.want, got)
		})
	}
}
