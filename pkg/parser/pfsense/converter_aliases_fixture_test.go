package pfsense_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParser_PfSenseAliasesFixture parses testdata/pfsense/pfsense-aliases.xml
// end-to-end through the pfSense Parser (not direct struct construction) and
// proves the top-level <aliases> subtree populates common.NamedObjects with
// the expected types and (space-separated) members.
//
// The fixture lives under testdata/pfsense/ (not the flat testdata/ root)
// alongside the other pfSense-only fixtures, since
// TestOpnSenseDocument_XMLCoverage (pkg/schema/opnsense) unmarshals every
// flat *.xml file directly under testdata/ as an OpnSenseDocument and would
// fail on a pfSense-rooted document.
func TestParser_PfSenseAliasesFixture(t *testing.T) {
	t.Parallel()

	fpath := filepath.Join("..", "..", "..", "testdata", "pfsense", "pfsense-aliases.xml")
	f, err := os.Open(fpath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	p := pfsense.NewParser(nil)
	device, warnings, err := p.Parse(context.Background(), f)
	require.NoError(t, err)
	assert.Empty(t, nonGapWarnings(warnings))
	require.NotNil(t, device)

	require.Len(t, device.NamedObjects, 6)

	webServers, ok := device.NamedObjects["WEB_SERVERS"]
	require.True(t, ok)
	assert.Equal(t, common.NamedObjectTypeHost, webServers.Type)
	assert.Equal(t, []string{"10.20.30.40", "10.20.30.41"}, webServers.Members)

	internalNet, ok := device.NamedObjects["INTERNAL_NET"]
	require.True(t, ok)
	assert.Equal(t, common.NamedObjectTypeNetwork, internalNet.Type)
	assert.Equal(t, []string{"10.20.0.0/16"}, internalNet.Members)

	webPorts, ok := device.NamedObjects["WEB_PORTS"]
	require.True(t, ok)
	assert.Equal(t, common.NamedObjectTypePort, webPorts.Type)
	assert.Equal(t, []string{"80", "443"}, webPorts.Members)

	allServers, ok := device.NamedObjects["ALL_SERVERS"]
	require.True(t, ok)
	assert.Equal(t, []string{"WEB_SERVERS", "10.20.30.50"}, allServers.Members)

	externalHosts, ok := device.NamedObjects["EXTERNAL_HOSTS"]
	require.True(t, ok)
	assert.Equal(t, []string{"203.0.113.10", "198.51.100.20"}, externalHosts.Members)

	mixedTypes, ok := device.NamedObjects["MIXED_TYPES"]
	require.True(t, ok)
	assert.Equal(t, common.NamedObjectTypeHost, mixedTypes.Type)
	assert.Equal(
		t,
		[]string{"10.20.30.60", "203.0.113.20", "198.51.100.0/24", "mail.example.org"},
		mixedTypes.Members,
	)

	require.Len(t, device.FirewallRules, 1)
	rule := device.FirewallRules[0]
	require.NotNil(t, rule.Source.AddressRef)
	assert.Equal(t, "WEB_SERVERS", rule.Source.AddressRef.Name)
	require.NotNil(t, rule.Destination.PortRef)
	assert.Equal(t, "WEB_PORTS", rule.Destination.PortRef.Name)
}
