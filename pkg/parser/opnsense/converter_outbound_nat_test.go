package opnsense_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseOutboundNAT drives one or more <nat><outbound><rule> bodies through
// parse and convert. The struct-built converter tests never noticed a flag the
// converter does not set (GOTCHAS §3.6), so these go through the XML.
func parseOutboundNAT(t *testing.T, rules string) *common.CommonDevice {
	t.Helper()

	const configTemplate = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>
  <interfaces>
    <wan><if>vtnet0</if></wan>
    <lan><if>vtnet1</if></lan>
  </interfaces>
  <nat><outbound><mode>advanced</mode>%s</outbound></nat>
</opnsense>`

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(
		context.Background(),
		strings.NewReader(strings.Replace(configTemplate, "%s", rules, 1)),
		common.DeviceTypeOPNsense,
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)

	return device
}

// TestConverter_OutboundNAT_KeepsNegation covers <not> on an outbound NAT
// rule's source and destination, which the firewall rule and port forward
// converters kept and this one dropped (#930).
func TestConverter_OutboundNAT_KeepsNegation(t *testing.T) {
	t.Parallel()

	const head = `<rule><interface>wan</interface><target>203.0.113.1</target>`

	tests := []struct {
		name    string
		rule    string
		wantSrc bool
		wantDst bool
	}{
		{
			name:    "negated source",
			rule:    head + `<source><network>lan</network><not>1</not></source><destination><any>1</any></destination></rule>`,
			wantSrc: true,
		},
		{
			name:    "negated destination",
			rule:    head + `<source><network>lan</network></source><destination><network>10.0.0.0/8</network><not>1</not></destination></rule>`,
			wantDst: true,
		},
		{
			name: "not zero is not negated",
			rule: head + `<source><network>lan</network><not>0</not></source><destination><any>1</any></destination></rule>`,
		},
		{
			name: "no not element",
			rule: head + `<source><network>lan</network></source><destination><any>1</any></destination></rule>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parseOutboundNAT(t, tt.rule)
			require.Len(t, device.NAT.OutboundRules, 1)

			rule := device.NAT.OutboundRules[0]
			assert.Equal(t, tt.wantSrc, rule.Source.Negated, "source negation")
			assert.Equal(t, tt.wantDst, rule.Destination.Negated, "destination negation")
			assert.Equal(t, "lan", rule.Source.Address, "the address must survive beside the flag")
		})
	}
}
