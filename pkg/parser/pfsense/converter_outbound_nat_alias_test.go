package pfsense_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// outboundAliasDoc is a pfSense config with three aliases and one outbound NAT
// rule, in the shape firewall_nat_out.inc writes: an alias on an outbound rule
// goes to <network>. An alias named lan shares the name of an interface macro.
func outboundAliasDoc(source, destination string) string {
	return `<?xml version="1.0"?><pfsense><aliases>` +
		`<alias><name>SOURCES</name><type>network</type><address>10.0.0.0/24</address></alias>` +
		`<alias><name>TARGETS</name><type>network</type><address>10.0.1.0/24</address></alias>` +
		`<alias><name>lan</name><type>network</type><address>10.0.2.0/24</address></alias>` +
		`</aliases><nat><outbound><mode>advanced</mode>` +
		`<rule><interface>wan</interface>` + source + destination + `</rule>` +
		`</outbound></nat></pfsense>`
}

func parseOutboundAliasDoc(t *testing.T, doc string) *common.CommonDevice {
	t.Helper()

	device, _, err := pfsense.NewParser(nil).Parse(context.Background(), strings.NewReader(doc))
	require.NoError(t, err)
	require.NotNil(t, device)

	return device
}

// TestConverter_OutboundNAT_AliasInNetwork decodes the shape the GUI writes. A
// rule in that shape used to carry no reference, so the alias read as unused.
func TestConverter_OutboundNAT_AliasInNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		source      string
		destination string
		wantSource  *common.ObjectRef
		wantDest    *common.ObjectRef
	}{
		{
			name:        "both in network, as the GUI writes them",
			source:      `<source><network>SOURCES</network></source>`,
			destination: `<destination><network>TARGETS</network></destination>`,
			wantSource:  &common.ObjectRef{Name: "SOURCES"},
			wantDest:    &common.ObjectRef{Name: "TARGETS"},
		},
		{
			name:        "both in address",
			source:      `<source><address>SOURCES</address></source>`,
			destination: `<destination><address>TARGETS</address></destination>`,
			wantSource:  &common.ObjectRef{Name: "SOURCES"},
			wantDest:    &common.ObjectRef{Name: "TARGETS"},
		},
		{
			name:        "literals carry no reference",
			source:      `<source><network>10.9.0.0/24</network></source>`,
			destination: `<destination><network>10.9.1.0/24</network></destination>`,
		},
		{
			name:        "any carries no reference",
			source:      `<source><network>any</network></source>`,
			destination: `<destination><any/></destination>`,
		},
		{
			// filter.inc tests the value with is_alias before anything else.
			name:        "a name that is both a macro and an alias is the alias",
			source:      `<source><network>lan</network></source>`,
			destination: `<destination><any/></destination>`,
			wantSource:  &common.ObjectRef{Name: "lan"},
		},
		{
			name:        "a macro no alias shares carries no reference",
			source:      `<source><network>wanip</network></source>`,
			destination: `<destination><any/></destination>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parseOutboundAliasDoc(t, outboundAliasDoc(tt.source, tt.destination))

			require.Len(t, device.NAT.OutboundRules, 1)
			assert.Equal(t, tt.wantSource, device.NAT.OutboundRules[0].Source.AddressRef)
			assert.Equal(t, tt.wantDest, device.NAT.OutboundRules[0].Destination.AddressRef)
		})
	}
}

// TestConverter_OutboundNAT_AliasInNetworkIsInUse pins what the reference is for.
func TestConverter_OutboundNAT_AliasInNetworkIsInUse(t *testing.T) {
	t.Parallel()

	device := parseOutboundAliasDoc(t, outboundAliasDoc(
		`<source><network>SOURCES</network></source>`,
		`<destination><network>TARGETS</network></destination>`))

	findings := analysis.DetectUnusedObjects(device)

	require.Len(t, findings, 1, "%+v", findings)
	assert.Equal(t, "lan", findings[0].Name)
}
