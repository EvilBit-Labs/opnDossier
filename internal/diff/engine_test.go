package diff

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPathInterfacesWanIP = "interfaces.wan.ipAddress"

func TestNewEngine(t *testing.T) {
	old := &common.CommonDevice{}
	newCfg := &common.CommonDevice{}
	opts := Options{}

	engine := NewEngine(old, newCfg, opts, nil)

	require.NotNil(t, engine)
	assert.Equal(t, old, engine.oldConfig)
	assert.Equal(t, newCfg, engine.newConfig)
	assert.NotNil(t, engine.analyzer)
}

func TestEngine_Compare_IdenticalConfigs(t *testing.T) {
	old := &common.CommonDevice{}
	old.System.Hostname = "firewall"
	old.System.Domain = "example.com"

	newCfg := &common.CommonDevice{}
	newCfg.System.Hostname = "firewall"
	newCfg.System.Domain = "example.com"

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.False(t, result.HasChanges())
	assert.Equal(t, 0, result.Summary.Total)
}

func TestEngine_Compare_HostnameChanged(t *testing.T) {
	old := &common.CommonDevice{}
	old.System.Hostname = "old-firewall"

	newCfg := &common.CommonDevice{}
	newCfg.System.Hostname = "new-firewall"

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Equal(t, 1, result.Summary.Modified)

	// Find the hostname change
	var found bool
	for _, change := range result.Changes {
		if change.Path == "system.hostname" {
			found = true
			assert.Equal(t, ChangeModified, change.Type)
			assert.Equal(t, "old-firewall", change.OldValue)
			assert.Equal(t, "new-firewall", change.NewValue)
		}
	}
	assert.True(t, found, "hostname change not found")
}

func TestEngine_Compare_SectionFiltering(t *testing.T) {
	old := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "10.0.0.1"},
		},
	}
	old.System.Hostname = "old-firewall"

	newCfg := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "10.0.0.2"},
		},
	}
	newCfg.System.Hostname = "new-firewall"

	// Only compare system section
	engine := NewEngine(old, newCfg, Options{Sections: []string{"system"}}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())

	// Should only have system changes, not interface changes
	for _, change := range result.Changes {
		assert.Equal(t, SectionSystem, change.Section)
	}
}

func TestEngine_Compare_ContextCancellation(t *testing.T) {
	old := &common.CommonDevice{}
	newCfg := &common.CommonDevice{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	engine := NewEngine(old, newCfg, Options{}, nil)
	_, err := engine.Compare(ctx)

	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestEngine_Compare_FirewallRuleAdded(t *testing.T) {
	old := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{},
	}

	newCfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{
				UUID:        "test-uuid-1",
				Type:        common.RuleTypePass,
				Description: "Allow SSH",
				Protocol:    "tcp",
				Destination: common.RuleEndpoint{
					Port: "22",
				},
			},
		},
	}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Equal(t, 1, result.Summary.Added)
}

func TestEngine_Compare_FirewallRuleRemoved(t *testing.T) {
	old := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{
				UUID:        "test-uuid-1",
				Type:        common.RuleTypePass,
				Description: "Legacy FTP",
				Protocol:    "tcp",
			},
		},
	}

	newCfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{},
	}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Equal(t, 1, result.Summary.Removed)
}

func TestEngine_Compare_InterfaceAdded(t *testing.T) {
	old := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "10.0.0.1", Description: "WAN"},
		},
	}

	newCfg := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "10.0.0.1", Description: "WAN"},
			{Name: "opt1", IPAddress: "192.168.10.1", Description: "DMZ"},
		},
	}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Equal(t, 1, result.Summary.Added)

	bySection := result.ChangesBySection()
	assert.Len(t, bySection[SectionInterfaces], 1)
	assert.Equal(t, ChangeAdded, bySection[SectionInterfaces][0].Type)
}

func TestEngine_Compare_InterfaceIPChanged(t *testing.T) {
	old := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "10.0.0.1", Subnet: "24", Description: "WAN"},
		},
	}

	newCfg := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "10.0.0.2", Subnet: "24", Description: "WAN"},
		},
	}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Equal(t, 1, result.Summary.Modified)

	// Find the IP change
	var found bool
	for _, change := range result.Changes {
		if change.Path == testPathInterfacesWanIP {
			found = true
			assert.Equal(t, "10.0.0.1", change.OldValue)
			assert.Equal(t, "10.0.0.2", change.NewValue)
		}
	}
	assert.True(t, found, "interface IP change not found")
}

func TestEngine_Compare_EmptyConfigs(t *testing.T) {
	old := &common.CommonDevice{}
	newCfg := &common.CommonDevice{}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.False(t, result.HasChanges())
	assert.NotNil(t, result.Metadata)
	assert.NotZero(t, result.Metadata.ComparedAt)
	assert.Equal(t, constants.Version, result.Metadata.ToolVersion)
}

func TestEngine_Compare_DetectOrder_ReorderedRules(t *testing.T) {
	old := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow SSH", Protocol: "tcp"},
			{UUID: "uuid-2", Type: common.RuleTypePass, Description: "Allow HTTP", Protocol: "tcp"},
			{UUID: "uuid-3", Type: common.RuleTypePass, Description: "Allow DNS", Protocol: "udp"},
		},
	}

	newCfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{UUID: "uuid-3", Type: common.RuleTypePass, Description: "Allow DNS", Protocol: "udp"},
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow SSH", Protocol: "tcp"},
			{UUID: "uuid-2", Type: common.RuleTypePass, Description: "Allow HTTP", Protocol: "tcp"},
		},
	}

	engine := NewEngine(old, newCfg, Options{DetectOrder: true}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Positive(t, result.Summary.Reordered, "should detect reordered rules")

	// Verify reorder changes have ChangeReordered type
	for _, c := range result.Changes {
		if c.Type == ChangeReordered {
			assert.Equal(t, SectionFirewall, c.Section)
			assert.Contains(t, c.Path, "filter.rule[uuid=")
		}
	}
}

func TestEngine_Compare_DetectOrder_Disabled(t *testing.T) {
	old := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow SSH", Protocol: "tcp"},
			{UUID: "uuid-2", Type: common.RuleTypePass, Description: "Allow HTTP", Protocol: "tcp"},
		},
	}

	newCfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{UUID: "uuid-2", Type: common.RuleTypePass, Description: "Allow HTTP", Protocol: "tcp"},
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow SSH", Protocol: "tcp"},
		},
	}

	// DetectOrder is false (default), so no reorder changes
	engine := NewEngine(old, newCfg, Options{DetectOrder: false}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 0, result.Summary.Reordered, "should not detect reorders when disabled")
}

func TestEngine_Compare_DetectOrder_ExcludesContentChanges(t *testing.T) {
	old := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow SSH", Protocol: "tcp"},
			{UUID: "uuid-2", Type: common.RuleTypePass, Description: "Allow HTTP", Protocol: "tcp"},
		},
	}

	newCfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			// uuid-2 moved to position 0 AND its description changed
			{UUID: "uuid-2", Type: common.RuleTypePass, Description: "Allow HTTPS", Protocol: "tcp"},
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow SSH", Protocol: "tcp"},
		},
	}

	engine := NewEngine(old, newCfg, Options{DetectOrder: true}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())

	// uuid-2 should appear as modified (content change), not also as reordered
	for _, c := range result.Changes {
		if c.Type == ChangeReordered && c.Path == "filter.rule[uuid=uuid-2]" {
			t.Error("uuid-2 should not appear as reordered when it also has content changes")
		}
	}
}

func TestEngine_Compare_Normalize_IPAddresses(t *testing.T) {
	old := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "010.000.001.001", Subnet: "24", Description: "WAN"},
		},
	}

	newCfg := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "010.000.001.002", Subnet: "24", Description: "WAN"},
		},
	}

	engine := NewEngine(old, newCfg, Options{Normalize: true}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())

	// Find the IP change - values should be normalized
	for _, c := range result.Changes {
		if c.Path == testPathInterfacesWanIP {
			assert.Equal(t, "10.0.1.1", c.OldValue, "old IP should be normalized")
			assert.Equal(t, "10.0.1.2", c.NewValue, "new IP should be normalized")
		}
	}
}

func TestEngine_Compare_Normalize_SkipsCosmeticDiffs(t *testing.T) {
	old := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "010.000.001.001", Subnet: "24", Description: "WAN"},
		},
	}

	newCfg := &common.CommonDevice{
		Interfaces: []common.Interface{
			// Same IP with different leading zeros - normalization makes them equal
			{Name: "wan", IPAddress: "10.0.1.1", Subnet: "24", Description: "WAN"},
		},
	}

	engine := NewEngine(old, newCfg, Options{Normalize: true}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)

	// The IP change should be skipped because normalized values are equal
	for _, c := range result.Changes {
		if c.Path == testPathInterfacesWanIP {
			t.Error("cosmetic IP difference should be skipped when normalize is enabled")
		}
	}
}

// summarizedDevice returns one entry of each kind whose displayed values are a
// summary, or absent.
func summarizedDevice() *common.CommonDevice {
	return &common.CommonDevice{
		FirewallRules: []common.FirewallRule{{
			UUID: "rule-1", Type: common.RuleTypePass, Interfaces: []string{"lan"}, Log: true,
			Source:      common.RuleEndpoint{Address: "lan"},
			Destination: common.RuleEndpoint{Address: constants.NetworkAny},
			Description: "Allow LAN",
		}},
		NAT: common.NATConfig{
			OutboundRules: []common.NATRule{{
				Interfaces: []string{"wan"}, Target: "203.0.113.1", Log: true,
				Source: common.RuleEndpoint{Address: "192.168.1.0/24"},
			}},
			InboundRules: []common.InboundNATRule{{
				Interfaces: []string{"wan"}, Protocol: "tcp", InternalIP: "192.168.1.10", LocalPort: "8443",
				Destination: common.RuleEndpoint{Address: "wanip", Port: "443"},
			}},
		},
		Users: []common.User{{Name: "alice", GroupName: "users"}},
	}
}

// TestEngine_Compare_Normalize_KeepsChangesTheTextDoesNotShow covers the four
// kinds of entry whose displayed values are a summary, or absent. A change to a
// field the summary omits leaves both values identical, and the normalize skip
// dropped every such entry.
func TestEngine_Compare_Normalize_KeepsChangesTheTextDoesNotShow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*common.CommonDevice)
		wantPath string
	}{
		{"firewall rule loses its logging", func(d *common.CommonDevice) {
			d.FirewallRules[0].Log = false
		}, "filter.rule[uuid=rule-1]"},
		{"firewall rule gateway redirected", func(d *common.CommonDevice) {
			d.FirewallRules[0].Gateway = "WAN2_GW"
		}, "filter.rule[uuid=rule-1]"},
		{"firewall rule description gains a doubled space", func(d *common.CommonDevice) {
			d.FirewallRules[0].Description = "Allow  LAN"
		}, "filter.rule[uuid=rule-1]"},
		{"outbound NAT rule loses its logging", func(d *common.CommonDevice) {
			d.NAT.OutboundRules[0].Log = false
		}, "nat.outbound.rules[0]"},
		{"port forward redirected to another port", func(d *common.CommonDevice) {
			d.NAT.InboundRules[0].LocalPort = "22"
		}, "nat.inbound.rules[0]"},
		{"user moved to another group", func(d *common.CommonDevice) {
			d.Users[0].GroupName = "admins"
		}, "system.user[alice]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oldDevice, newDevice := summarizedDevice(), summarizedDevice()
			tt.mutate(newDevice)

			result, err := NewEngine(oldDevice, newDevice, Options{Normalize: true}, nil).Compare(context.Background())
			require.NoError(t, err)
			require.Len(t, result.Changes, 1)
			assert.Equal(t, ChangeModified, result.Changes[0].Type)
			assert.Equal(t, tt.wantPath, result.Changes[0].Path)
			assert.Equal(t, result.Changes[0].OldValue, result.Changes[0].NewValue,
				"the case is only covered while the displayed values are identical")
		})
	}
}

// TestEngine_Compare_Normalize_KeepsChangeBehindSummaryWhitespace covers a
// summary that differs only in whitespace while a field it omits changed too.
// The whitespace normalizer makes the two summaries equal, and the entry must
// stay.
func TestEngine_Compare_Normalize_KeepsChangeBehindSummaryWhitespace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		edit     func(oldDevice, newDevice *common.CommonDevice)
		wantPath string
	}{
		{"firewall rule loses its logging", func(o, n *common.CommonDevice) {
			o.FirewallRules[0].Destination.Port, n.FirewallRules[0].Destination.Port = "443 ", "443"
			n.FirewallRules[0].Log = false
		}, "filter.rule[uuid=rule-1]"},
		{"firewall rule without a uuid reverses direction", func(o, n *common.CommonDevice) {
			o.FirewallRules[0].UUID, n.FirewallRules[0].UUID = "", ""
			o.FirewallRules[0].Source.Address, n.FirewallRules[0].Source.Address = "lan  net", "lan net"
			n.FirewallRules[0].Direction = common.DirectionOut
		}, "filter.rule[0]"},
		{"outbound NAT rule loses its logging", func(o, n *common.CommonDevice) {
			o.NAT.OutboundRules[0].Target = "203.0.113.1\n"
			n.NAT.OutboundRules[0].Log = false
		}, "nat.outbound.rules[0]"},
		{"port forward redirected to another port", func(o, n *common.CommonDevice) {
			o.NAT.InboundRules[0].InternalIP = "192.168.1.10 "
			n.NAT.InboundRules[0].LocalPort = "22"
		}, "nat.inbound.rules[0]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			oldDevice, newDevice := summarizedDevice(), summarizedDevice()
			tt.edit(oldDevice, newDevice)

			raw, err := NewEngine(oldDevice, newDevice, Options{}, nil).Compare(context.Background())
			require.NoError(t, err)
			require.Len(t, raw.Changes, 1)
			require.NotEqual(t, raw.Changes[0].OldValue, raw.Changes[0].NewValue,
				"the case is only covered while the summaries differ")

			result, err := NewEngine(oldDevice, newDevice, Options{Normalize: true}, nil).Compare(context.Background())
			require.NoError(t, err)
			require.Len(t, result.Changes, 1)
			assert.Equal(t, tt.wantPath, result.Changes[0].Path)
			assert.Equal(t, result.Changes[0].OldValue, result.Changes[0].NewValue,
				"the case is only covered while whitespace is the whole difference in the summaries")
		})
	}
}

// TestEngine_Compare_Normalize_SkipsFormattingInEitherDirection runs each
// formatting-only edit without the option, where it is reported, and with it.
func TestEngine_Compare_Normalize_SkipsFormattingInEitherDirection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		old      common.Interface
		newIface common.Interface
		wantPath string
	}{
		{
			"address loses its leading zeros",
			common.Interface{IPAddress: "010.000.001.001"},
			common.Interface{IPAddress: "10.0.1.1"},
			testPathInterfacesWanIP,
		},
		{
			"address gains leading zeros",
			common.Interface{IPAddress: "10.0.1.1"},
			common.Interface{IPAddress: "010.000.001.001"},
			testPathInterfacesWanIP,
		},
		{
			"subnet loses its leading zero",
			common.Interface{Subnet: "024"},
			common.Interface{Subnet: "24"},
			"interfaces.wan.subnet",
		},
		{
			"description loses a doubled space",
			common.Interface{Description: "Guest  WiFi"},
			common.Interface{Description: "Guest WiFi"},
			"interfaces.wan.description",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.old.Name, tt.newIface.Name = "wan", "wan"
			oldDevice := &common.CommonDevice{Interfaces: []common.Interface{tt.old}}
			newDevice := &common.CommonDevice{Interfaces: []common.Interface{tt.newIface}}

			raw, err := NewEngine(oldDevice, newDevice, Options{}, nil).Compare(context.Background())
			require.NoError(t, err)
			require.Len(t, raw.Changes, 1)
			assert.Equal(t, tt.wantPath, raw.Changes[0].Path)

			result, err := NewEngine(oldDevice, newDevice, Options{Normalize: true}, nil).Compare(context.Background())
			require.NoError(t, err)
			assert.Empty(t, result.Changes)
		})
	}
}

// TestEngine_Compare_Normalize_DropsOnlyTheFormattingChange mixes the kinds: an
// address rewritten without its leading zeros, a real change to the same
// interface after it, and a rule that loses its logging.
func TestEngine_Compare_Normalize_DropsOnlyTheFormattingChange(t *testing.T) {
	t.Parallel()

	device := func(address, description string, log bool) *common.CommonDevice {
		return &common.CommonDevice{
			Interfaces: []common.Interface{{Name: "wan", IPAddress: address, Subnet: "24", Description: description}},
			FirewallRules: []common.FirewallRule{{
				UUID: "rule-1", Type: common.RuleTypePass, Interfaces: []string{"lan"}, Log: log,
				Source:      common.RuleEndpoint{Address: "lan"},
				Destination: common.RuleEndpoint{Address: constants.NetworkAny},
			}},
		}
	}

	oldDevice, newDevice := device("010.000.001.001", "WAN", true), device("10.0.1.1", "Uplink", false)

	tests := []struct {
		opts      Options
		wantPaths []string
	}{
		{Options{}, []string{"filter.rule[uuid=rule-1]", testPathInterfacesWanIP, "interfaces.wan.description"}},
		{Options{Normalize: true}, []string{"filter.rule[uuid=rule-1]", "interfaces.wan.description"}},
	}

	for _, tt := range tests {
		result, err := NewEngine(oldDevice, newDevice, tt.opts, nil).Compare(context.Background())
		require.NoError(t, err)

		paths := make([]string, 0, len(result.Changes))
		for _, c := range result.Changes {
			paths = append(paths, c.Path)
		}

		assert.Equal(t, tt.wantPaths, paths, "normalize=%t", tt.opts.Normalize)
	}
}

// TestEngine_Compare_Normalize_ShippedConfigs_KeepUserChange runs the case
// through the parser. Between these two shipped configs the one difference in
// the users section is that root's API key was replaced.
func TestEngine_Compare_Normalize_ShippedConfigs_KeepUserChange(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata")
	oldDevice := parseFixture(t, filepath.Join(root, "sample.config.2.xml"))
	newDevice := parseFixture(t, filepath.Join(root, "sample.config.4.xml"))

	for _, normalize := range []bool{false, true} {
		opts := Options{Normalize: normalize, Sections: []string{"users"}}
		result, err := NewEngine(oldDevice, newDevice, opts, nil).Compare(context.Background())
		require.NoError(t, err)
		require.Len(t, result.Changes, 1, "normalize=%t", normalize)
		assert.Equal(t, "system.user[root]", result.Changes[0].Path)
	}
}

// TestEngine_Compare_Normalize_ShippedConfig_KeepsRedirectedPortForward runs
// the whitespace case through the parser: the old config carries a trailing
// space in the port forward's target, and the new one sends it to port 22.
func TestEngine_Compare_Normalize_ShippedConfig_KeepsRedirectedPortForward(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "pfsense", "config-2.6.x.xml"))
	require.NoError(t, err)

	const target, localPort = "<target>192.168.1.50</target>", "<local-port>8080</local-port>"
	require.Equal(t, 1, bytes.Count(data, []byte(target)))
	require.Equal(t, 1, bytes.Count(data, []byte(localPort)))

	parse := func(from, to string) *common.CommonDevice {
		edited := bytes.NewReader(bytes.Replace(data, []byte(from), []byte(to), 1))
		device, _, parseErr := parser.NewFactory(cfgparser.NewXMLParser()).
			CreateDevice(context.Background(), edited, common.DeviceTypeUnknown, false)
		require.NoError(t, parseErr)

		return device
	}
	oldDevice := parse(target, "<target>192.168.1.50 </target>")
	newDevice := parse(localPort, "<local-port>22</local-port>")
	require.Equal(t, "192.168.1.50 ", oldDevice.NAT.InboundRules[0].InternalIP,
		"the case is only covered while the parser keeps the trailing space")

	result, err := NewEngine(oldDevice, newDevice, Options{Normalize: true}, nil).Compare(context.Background())
	require.NoError(t, err)
	require.Len(t, result.Changes, 1)
	assert.Equal(t, "nat.inbound.rules[0]", result.Changes[0].Path)
	assert.Equal(t, "medium", result.Changes[0].SecurityImpact)
	require.Equal(t, result.Changes[0].OldValue, result.Changes[0].NewValue,
		"the case is only covered while whitespace is the whole difference in the summaries")
}

// TestFormattingOnly pins each clause of the skip.
func TestFormattingOnly(t *testing.T) {
	t.Parallel()

	const zeros, plain = "010.000.001.001", "10.0.1.1"

	modified := func(oldValue, newValue string) Change {
		return Change{Type: ChangeModified, OldValue: oldValue, NewValue: newValue}
	}
	summarized := modified("a  b", "a b")
	summarized.summarized = true

	tests := []struct {
		name             string
		change           Change
		normOld, normNew string
		want             bool
	}{
		{"old value rewritten", modified(zeros, plain), plain, plain, true},
		{"new value rewritten", modified(plain, zeros), plain, plain, true},
		{"both values rewritten", modified("010.0.1.1", "10.00.1.1"), plain, plain, true},
		{"values differ after normalization", modified(zeros, "10.0.1.2"), plain, "10.0.1.2", false},
		{"values already equal", modified(plain, plain), plain, plain, false},
		{"equal values that normalization rewrites", modified("a  b", "a  b"), "a b", "a b", false},
		{"no values", modified("", ""), "", "", false},
		{"summarized", summarized, "a b", "a b", false},
		{"added", Change{Type: ChangeAdded, NewValue: " "}, "", "", false},
		{"removed", Change{Type: ChangeRemoved, OldValue: " "}, "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, formattingOnly(tt.change, tt.normOld, tt.normNew))
		})
	}
}

func TestEngine_Compare_RiskSummary_Populated(t *testing.T) {
	old := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{},
	}

	newCfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow any", Protocol: "any"},
		},
	}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	// Risk summary should be computed (score may vary based on patterns)
	assert.NotNil(t, result.RiskSummary)
}
