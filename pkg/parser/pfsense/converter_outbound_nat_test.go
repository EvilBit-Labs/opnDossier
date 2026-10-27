package pfsense_test

import (
	"context"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parsePfSenseOutboundNAT drives one <nat><outbound><rule> body through the
// pfSense parser and returns the converted rule.
func parsePfSenseOutboundNAT(t *testing.T, ruleBody string) common.NATRule {
	t.Helper()

	const configTemplate = `<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <nat><outbound><mode>advanced</mode><rule><interface>wan</interface>%s</rule></outbound></nat>
</pfsense>`

	device, _, err := pfsense.NewParser(nil).Parse(
		context.Background(),
		strings.NewReader(strings.Replace(configTemplate, "%s", ruleBody, 1)),
	)
	require.NoError(t, err)
	require.NotNil(t, device)
	require.Len(t, device.NAT.OutboundRules, 1)

	return device.NAT.OutboundRules[0]
}

// TestConverter_OutboundNAT_KeepsNegation covers <not> on an outbound NAT
// rule's endpoints (#930). pfSense writes the flag as an empty element, and
// its 2.7.2 editor only exposes it for the destination, but the schema and
// the writer accept it on either side.
func TestConverter_OutboundNAT_KeepsNegation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		wantSrc bool
		wantDst bool
	}{
		{
			name:    "negated destination",
			body:    `<source><network>lan</network></source><destination><network>10.0.0.0/8</network><not></not></destination>`,
			wantDst: true,
		},
		{
			name:    "negated source",
			body:    `<source><network>lan</network><not></not></source><destination><any></any></destination>`,
			wantSrc: true,
		},
		{
			name: "no not element",
			body: `<source><network>lan</network></source><destination><any></any></destination>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := parsePfSenseOutboundNAT(t, tt.body)
			assert.Equal(t, tt.wantSrc, rule.Source.Negated, "source negation")
			assert.Equal(t, tt.wantDst, rule.Destination.Negated, "destination negation")
			assert.Equal(t, "lan", rule.Source.Address, "the address must survive beside the flag")
		})
	}
}
