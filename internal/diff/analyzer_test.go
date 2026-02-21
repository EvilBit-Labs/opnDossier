package diff

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
)

func TestNewAnalyzer(t *testing.T) {
	analyzer := NewAnalyzer()
	assert.NotNil(t, analyzer)
}

func TestAnalyzer_CompareSystem_NoChanges(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &common.System{
		Hostname: "firewall",
		Domain:   "example.com",
		Timezone: "UTC",
	}
	newCfg := &common.System{
		Hostname: "firewall",
		Domain:   "example.com",
		Timezone: "UTC",
	}

	changes := analyzer.CompareSystem(old, newCfg)
	assert.Empty(t, changes)
}

func TestAnalyzer_CompareSystem_HostnameChanged(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &common.System{Hostname: "old-firewall"}
	newCfg := &common.System{Hostname: "new-firewall"}

	changes := analyzer.CompareSystem(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Equal(t, "system.hostname", changes[0].Path)
	assert.Equal(t, "old-firewall", changes[0].OldValue)
	assert.Equal(t, "new-firewall", changes[0].NewValue)
}

func TestAnalyzer_CompareSystem_MultipleChanges(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &common.System{
		Hostname: "old-host",
		Domain:   "old.com",
		Timezone: "UTC",
	}
	newCfg := &common.System{
		Hostname: "new-host",
		Domain:   "new.com",
		Timezone: "America/New_York",
	}

	changes := analyzer.CompareSystem(old, newCfg)

	assert.Len(t, changes, 3)
}

func TestAnalyzer_CompareSystem_WebGUIProtocolChange(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &common.System{
		WebGUI: common.WebGUI{Protocol: "http"},
	}
	newCfg := &common.System{
		WebGUI: common.WebGUI{Protocol: "https"},
	}

	changes := analyzer.CompareSystem(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, "medium", changes[0].SecurityImpact)
}

func TestAnalyzer_CompareFirewallRules_NoChanges(t *testing.T) {
	analyzer := NewAnalyzer()
	rules := []common.FirewallRule{
		{UUID: "uuid-1", Type: "pass", Description: "Allow SSH"},
	}

	changes := analyzer.CompareFirewallRules(rules, rules)
	assert.Empty(t, changes)
}

func TestAnalyzer_CompareFirewallRules_RuleAdded(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []common.FirewallRule{}
	newCfg := []common.FirewallRule{
		{UUID: "uuid-1", Type: "pass", Description: "Allow SSH"},
	}

	changes := analyzer.CompareFirewallRules(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.Contains(t, changes[0].Description, "Allow SSH")
}

func TestAnalyzer_CompareFirewallRules_RuleRemoved(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []common.FirewallRule{
		{UUID: "uuid-1", Type: "pass", Description: "Legacy FTP"},
	}
	newCfg := []common.FirewallRule{}

	changes := analyzer.CompareFirewallRules(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)
	assert.Contains(t, changes[0].Description, "Legacy FTP")
	assert.Equal(t, "medium", changes[0].SecurityImpact)
}

func TestAnalyzer_CompareFirewallRules_RuleModified(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []common.FirewallRule{
		{UUID: "uuid-1", Type: "pass", Description: "Allow SSH", Protocol: "tcp"},
	}
	newCfg := []common.FirewallRule{
		{UUID: "uuid-1", Type: "pass", Description: "Allow SSH", Protocol: "udp"},
	}

	changes := analyzer.CompareFirewallRules(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
}

func TestAnalyzer_CompareFirewallRules_PermissiveRuleAdded(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []common.FirewallRule{}
	newCfg := []common.FirewallRule{
		{
			UUID:        "uuid-1",
			Type:        "pass",
			Source:      common.RuleEndpoint{Address: "any"},
			Destination: common.RuleEndpoint{Address: "any"},
		},
	}

	changes := analyzer.CompareFirewallRules(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, "high", changes[0].SecurityImpact)
}

func TestAnalyzer_CompareInterfaces_NoChanges(t *testing.T) {
	analyzer := NewAnalyzer()
	interfaces := []common.Interface{
		{Name: "wan", IPAddress: "10.0.0.1", Subnet: "24"},
	}

	changes := analyzer.CompareInterfaces(interfaces, interfaces)
	assert.Empty(t, changes)
}

func TestAnalyzer_CompareInterfaces_InterfaceAdded(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []common.Interface{
		{Name: "wan", IPAddress: "10.0.0.1"},
	}
	newCfg := []common.Interface{
		{Name: "wan", IPAddress: "10.0.0.1"},
		{Name: "opt1", IPAddress: "192.168.10.1", Description: "DMZ"},
	}

	changes := analyzer.CompareInterfaces(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.Contains(t, changes[0].Path, "opt1")
}

func TestAnalyzer_CompareInterfaces_InterfaceRemoved(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []common.Interface{
		{Name: "wan", IPAddress: "10.0.0.1"},
		{Name: "opt1", IPAddress: "192.168.10.1", Description: "DMZ"},
	}
	newCfg := []common.Interface{
		{Name: "wan", IPAddress: "10.0.0.1"},
	}

	changes := analyzer.CompareInterfaces(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)
	assert.Contains(t, changes[0].Path, "opt1")
}

func TestAnalyzer_CompareInterfaces_IPChanged(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []common.Interface{
		{Name: "wan", IPAddress: "10.0.0.1", Subnet: "24"},
	}
	newCfg := []common.Interface{
		{Name: "wan", IPAddress: "10.0.0.2", Subnet: "24"},
	}

	changes := analyzer.CompareInterfaces(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Equal(t, "interfaces.wan.ipAddress", changes[0].Path)
}

func TestAnalyzer_CompareVLANs_NoChanges(t *testing.T) {
	analyzer := NewAnalyzer()
	vlans := []common.VLAN{
		{VLANIf: "vlan10", Tag: "10", PhysicalIf: "em0"},
	}

	changes := analyzer.CompareVLANs(vlans, vlans)
	assert.Empty(t, changes)
}

func TestAnalyzer_CompareVLANs_VLANAdded(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []common.VLAN{}
	newCfg := []common.VLAN{
		{VLANIf: "vlan10", Tag: "10", PhysicalIf: "em0", Description: "Guest"},
	}

	changes := analyzer.CompareVLANs(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.Contains(t, changes[0].Description, "vlan10")
}

func TestAnalyzer_CompareVLANs_VLANRemoved(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []common.VLAN{
		{VLANIf: "vlan10", Tag: "10", PhysicalIf: "em0"},
	}
	newCfg := []common.VLAN{}

	changes := analyzer.CompareVLANs(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)
}

func TestAnalyzer_CompareVLANs_TagChanged(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []common.VLAN{
		{VLANIf: "vlan10", Tag: "10", PhysicalIf: "em0"},
	}
	newCfg := []common.VLAN{
		{VLANIf: "vlan10", Tag: "20", PhysicalIf: "em0"},
	}

	changes := analyzer.CompareVLANs(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Contains(t, changes[0].Path, "tag")
}

func TestAnalyzer_CompareUsers_NoChanges(t *testing.T) {
	analyzer := NewAnalyzer()
	users := []common.User{
		{Name: "admin", Scope: "system", GroupName: "admins"},
	}

	changes := analyzer.CompareUsers(users, users)
	assert.Empty(t, changes)
}

func TestAnalyzer_CompareUsers_UserAdded(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []common.User{}
	newCfg := []common.User{
		{Name: "admin", Scope: "system", GroupName: "admins", Description: "Administrator"},
	}

	changes := analyzer.CompareUsers(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.Equal(t, "medium", changes[0].SecurityImpact)
}

func TestAnalyzer_CompareUsers_UserRemoved(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []common.User{
		{Name: "olduser", Scope: "local", GroupName: "users"},
	}
	newCfg := []common.User{}

	changes := analyzer.CompareUsers(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)
	assert.Equal(t, "medium", changes[0].SecurityImpact)
}

func TestAnalyzer_CompareNAT_ModeChanged(t *testing.T) {
	analyzer := NewAnalyzer()
	old := common.NATConfig{
		OutboundMode: "automatic",
	}
	newCfg := common.NATConfig{
		OutboundMode: "hybrid",
	}

	changes := analyzer.CompareNAT(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Equal(t, "medium", changes[0].SecurityImpact)
}

func TestFormatEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ep   common.RuleEndpoint
		want string
	}{
		{
			name: "address only",
			ep:   common.RuleEndpoint{Address: "lan"},
			want: "lan",
		},
		{
			name: "specific address",
			ep:   common.RuleEndpoint{Address: "10.0.0.1"},
			want: "10.0.0.1",
		},
		{
			name: "any address",
			ep:   common.RuleEndpoint{Address: "any"},
			want: "any",
		},
		{
			name: "empty endpoint",
			ep:   common.RuleEndpoint{},
			want: "unknown",
		},
		{
			name: "negated address",
			ep:   common.RuleEndpoint{Address: "lan", Negated: true},
			want: "!lan",
		},
		{
			name: "negated address with port",
			ep:   common.RuleEndpoint{Address: "192.168.1.0/24", Negated: true, Port: "22"},
			want: "!192.168.1.0/24:22",
		},
		{
			name: "address with port",
			ep:   common.RuleEndpoint{Address: "wan", Port: "443"},
			want: "wan:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatEndpoint(tt.ep)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule common.FirewallRule
		want string
	}{
		{
			name: "basic pass rule",
			rule: common.FirewallRule{
				Type:        "pass",
				Interfaces:  []string{"wan"},
				Protocol:    "tcp",
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "lan", Port: "443"},
			},
			want: "type=pass, if=wan, proto=tcp, src=any, dst=lan:443",
		},
		{
			name: "disabled rule",
			rule: common.FirewallRule{
				Type:        "block",
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "any"},
				Disabled:    true,
			},
			want: "type=block, src=any, dst=any, disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatRule(tt.rule)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRuleDescription(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule common.FirewallRule
		want string
	}{
		{
			name: "with description",
			rule: common.FirewallRule{Description: "Allow SSH"},
			want: "Allow SSH",
		},
		{
			name: "without description uses address",
			rule: common.FirewallRule{
				Type:        "pass",
				Source:      common.RuleEndpoint{Address: "10.0.0.0/8"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
			want: "pass 10.0.0.0/8 → any",
		},
		{
			name: "empty addresses fall back to unknown",
			rule: common.FirewallRule{
				Type: "block",
			},
			want: "block unknown → unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ruleDescription(tt.rule)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAnalyzer_CompareRoutes_CountChanged(t *testing.T) {
	analyzer := NewAnalyzer()
	old := common.Routing{
		StaticRoutes: []common.StaticRoute{
			{Network: "10.0.0.0/8"},
		},
	}
	newCfg := common.Routing{
		StaticRoutes: []common.StaticRoute{
			{Network: "10.0.0.0/8"},
			{Network: "172.16.0.0/12"},
		},
	}

	changes := analyzer.CompareRoutes(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Equal(t, SectionRouting, changes[0].Section)
}

func TestIsPermissiveRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule common.FirewallRule
		want bool
	}{
		{
			name: "any/any pass rule",
			rule: common.FirewallRule{
				Type:        "pass",
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
			want: true,
		},
		{
			name: "block rule is not permissive",
			rule: common.FirewallRule{
				Type:        "block",
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
			want: false,
		},
		{
			name: "specific source is not permissive",
			rule: common.FirewallRule{
				Type:        "pass",
				Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isPermissiveRule(tt.rule)
			assert.Equal(t, tt.want, got)
		})
	}
}
