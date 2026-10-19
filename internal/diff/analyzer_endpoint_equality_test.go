package diff

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// aliasFixture is the shipped config whose firewall rule names an address alias
// and a port alias.
const aliasFixture = "pfsense-aliases.xml"

// aliasEndpoint returns an endpoint that names an address alias and a port
// alias. Each call allocates its own references, the way each parse of a config
// does.
func aliasEndpoint(address, port string) common.RuleEndpoint {
	return common.RuleEndpoint{
		Address:    address,
		AddressRef: &common.ObjectRef{Name: address},
		Port:       port,
		PortRef:    &common.ObjectRef{Name: port},
	}
}

// aliasDevice returns a device whose firewall rule, outbound NAT rule and port
// forward all name aliases on both endpoints. Two calls return equal content
// held in separate allocations.
func aliasDevice() *common.CommonDevice {
	return &common.CommonDevice{
		FirewallRules: []common.FirewallRule{{
			Type: common.RuleTypePass, Description: "web", Interfaces: []string{"wan"}, Protocol: "tcp",
			Source:      aliasEndpoint("TRUSTED_NETS", "CLIENT_PORTS"),
			Destination: aliasEndpoint("WEB_HOSTS", "WEB_PORTS"),
		}},
		NAT: common.NATConfig{
			OutboundMode: common.OutboundAdvanced,
			OutboundRules: []common.NATRule{{
				Interfaces: []string{"wan"}, Description: "lan egress", Target: "203.0.113.1",
				Source:      aliasEndpoint("LAN_NETS", "CLIENT_PORTS"),
				Destination: aliasEndpoint("UPSTREAMS", "WEB_PORTS"),
			}},
			InboundRules: []common.InboundNATRule{{
				Interfaces: []string{"wan"}, Protocol: "tcp", Description: "web forward", InternalIP: "192.168.1.10",
				Source:      aliasEndpoint("TRUSTED_NETS", "CLIENT_PORTS"),
				Destination: aliasEndpoint("WAN_ADDRESSES", "WEB_PORTS"),
			}},
		},
	}
}

// TestEndpointsEqual_ComparesEveryField is the coverage guard for the endpoint
// helper, like the ones on the rule helpers that call it.
func TestEndpointsEqual_ComparesEveryField(t *testing.T) {
	t.Parallel()

	assertEqualityCoversEveryField(t, endpointsEqual, nil)
}

// TestCompare_UnchangedAliasEndpoints_ProduceNoChange covers a config diffed
// against a second parse of itself. The rule helpers compared endpoints with
// ==, which compares the alias reference pointers, so every rule naming an
// alias in its source or destination was reported as modified with identical
// old and new values.
func TestCompare_UnchangedAliasEndpoints_ProduceNoChange(t *testing.T) {
	t.Parallel()

	oldDevice, newDevice := aliasDevice(), aliasDevice()

	assert.True(t, rulesEqual(oldDevice.FirewallRules[0], newDevice.FirewallRules[0]))
	assert.True(t, natRulesEqual(oldDevice.NAT.OutboundRules[0], newDevice.NAT.OutboundRules[0]))
	assert.True(t, inboundNATRulesEqual(oldDevice.NAT.InboundRules[0], newDevice.NAT.InboundRules[0]))

	result, err := NewEngine(oldDevice, newDevice, Options{}, nil).Compare(context.Background())
	require.NoError(t, err)
	assert.Empty(t, result.Changes)
}

// TestCompare_AliasSwappedOnEndpoint_IsReported is the other half: comparing by
// value must still notice an endpoint that moves to another alias, on each of
// the three rule kinds and for the address and the port.
func TestCompare_AliasSwappedOnEndpoint_IsReported(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mutate      func(*common.CommonDevice)
		wantSection Section
	}{
		{"firewall rule source alias", func(d *common.CommonDevice) {
			d.FirewallRules[0].Source = aliasEndpoint("OTHER_NETS", "CLIENT_PORTS")
		}, SectionFirewall},
		{"firewall rule destination port alias", func(d *common.CommonDevice) {
			d.FirewallRules[0].Destination.PortRef = &common.ObjectRef{Name: "OTHER_PORTS"}
		}, SectionFirewall},
		{"outbound NAT destination alias", func(d *common.CommonDevice) {
			d.NAT.OutboundRules[0].Destination = aliasEndpoint("OTHER_UPSTREAMS", "WEB_PORTS")
		}, SectionNAT},
		{"port forward source alias reference dropped", func(d *common.CommonDevice) {
			d.NAT.InboundRules[0].Source.AddressRef = nil
		}, SectionNAT},
		{"port forward destination port alias", func(d *common.CommonDevice) {
			d.NAT.InboundRules[0].Destination = aliasEndpoint("WAN_ADDRESSES", "OTHER_PORTS")
		}, SectionNAT},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oldDevice, newDevice := aliasDevice(), aliasDevice()
			tt.mutate(newDevice)

			result, err := NewEngine(oldDevice, newDevice, Options{}, nil).Compare(context.Background())
			require.NoError(t, err)
			require.Len(t, result.Changes, 1)
			assert.Equal(t, ChangeModified, result.Changes[0].Type)
			assert.Equal(t, tt.wantSection, result.Changes[0].Section)
		})
	}
}

// parseFixture parses a config through the device factory, as the CLI does.
func parseFixture(t *testing.T, path string) *common.CommonDevice {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).
		CreateDevice(context.Background(), bytes.NewReader(data), common.DeviceTypeUnknown, false)
	require.NoError(t, err)

	return device
}

// TestCompare_TwoParsesOfOneConfig_ProduceNoChange diffs every shipped config
// against a second parse of itself. The tests above build their devices by
// hand; this one covers what the converters allocate, for every comparison the
// engine makes.
func TestCompare_TwoParsesOfOneConfig_ProduceNoChange(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata")

	paths, err := filepath.Glob(filepath.Join(root, "*.xml"))
	require.NoError(t, err)

	pfSense, err := filepath.Glob(filepath.Join(root, "pfsense", "*.xml"))
	require.NoError(t, err)

	paths = append(paths, pfSense...)
	require.Contains(t, paths, filepath.Join(root, "pfsense", aliasFixture))

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()

			oldDevice, newDevice := parseFixture(t, path), parseFixture(t, path)

			if filepath.Base(path) == aliasFixture {
				// Without a reference on each side this config would pass
				// whatever the helpers compare.
				require.NotEmpty(t, oldDevice.FirewallRules)
				require.NotNil(t, oldDevice.FirewallRules[0].Source.AddressRef)
				require.NotNil(t, oldDevice.FirewallRules[0].Destination.PortRef)
			}

			result, err := NewEngine(oldDevice, newDevice, Options{}, nil).Compare(context.Background())
			require.NoError(t, err)
			assert.Empty(t, result.Changes)
		})
	}
}
