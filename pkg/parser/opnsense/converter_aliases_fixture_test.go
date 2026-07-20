package opnsense_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParser_OPNsenseAliasesFixture parses testdata/opnsense-aliases.xml
// end-to-end through the full parser pipeline (not direct struct
// construction) and proves the MVC Firewall/Alias subtree populates
// common.NamedObjects with the expected types and members.
func TestParser_OPNsenseAliasesFixture(t *testing.T) {
	t.Parallel()

	fpath := filepath.Join("..", "..", "..", "testdata", "opnsense-aliases.xml")
	f, err := os.Open(fpath)
	require.NoError(t, err)
	defer f.Close()

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(context.Background(), f, common.DeviceTypeUnknown, false)
	require.NoError(t, err)
	assert.Empty(t, warnings)
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
}
