package diff

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/schema"
	"github.com/stretchr/testify/assert"
)

func TestNewAnalyzer(t *testing.T) {
	analyzer := NewAnalyzer()
	assert.NotNil(t, analyzer)
}

func TestAnalyzer_CompareSystem_NoChanges(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &schema.System{
		Hostname: "firewall",
		Domain:   "example.com",
		Timezone: "UTC",
	}
	newCfg := &schema.System{
		Hostname: "firewall",
		Domain:   "example.com",
		Timezone: "UTC",
	}

	changes := analyzer.CompareSystem(old, newCfg)
	assert.Empty(t, changes)
}

func TestAnalyzer_CompareSystem_HostnameChanged(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &schema.System{Hostname: "old-firewall"}
	newCfg := &schema.System{Hostname: "new-firewall"}

	changes := analyzer.CompareSystem(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Equal(t, "system.hostname", changes[0].Path)
	assert.Equal(t, "old-firewall", changes[0].OldValue)
	assert.Equal(t, "new-firewall", changes[0].NewValue)
}

func TestAnalyzer_CompareSystem_MultipleChanges(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &schema.System{
		Hostname: "old-host",
		Domain:   "old.com",
		Timezone: "UTC",
	}
	newCfg := &schema.System{
		Hostname: "new-host",
		Domain:   "new.com",
		Timezone: "America/New_York",
	}

	changes := analyzer.CompareSystem(old, newCfg)

	assert.Len(t, changes, 3)
}

func TestAnalyzer_CompareSystem_WebGUIProtocolChange(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &schema.System{
		WebGUI: schema.WebGUIConfig{Protocol: "http"},
	}
	newCfg := &schema.System{
		WebGUI: schema.WebGUIConfig{Protocol: "https"},
	}

	changes := analyzer.CompareSystem(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, "medium", changes[0].SecurityImpact)
}

func TestAnalyzer_CompareFirewallRules_NoChanges(t *testing.T) {
	analyzer := NewAnalyzer()
	rules := []schema.Rule{
		{UUID: "uuid-1", Type: "pass", Descr: "Allow SSH"},
	}

	changes := analyzer.CompareFirewallRules(rules, rules)
	assert.Empty(t, changes)
}

func TestAnalyzer_CompareFirewallRules_RuleAdded(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []schema.Rule{}
	newCfg := []schema.Rule{
		{UUID: "uuid-1", Type: "pass", Descr: "Allow SSH"},
	}

	changes := analyzer.CompareFirewallRules(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.Contains(t, changes[0].Description, "Allow SSH")
}

func TestAnalyzer_CompareFirewallRules_RuleRemoved(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []schema.Rule{
		{UUID: "uuid-1", Type: "pass", Descr: "Legacy FTP"},
	}
	newCfg := []schema.Rule{}

	changes := analyzer.CompareFirewallRules(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)
	assert.Contains(t, changes[0].Description, "Legacy FTP")
	assert.Equal(t, "medium", changes[0].SecurityImpact)
}

func TestAnalyzer_CompareFirewallRules_RuleModified(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []schema.Rule{
		{UUID: "uuid-1", Type: "pass", Descr: "Allow SSH", Protocol: "tcp"},
	}
	newCfg := []schema.Rule{
		{UUID: "uuid-1", Type: "pass", Descr: "Allow SSH", Protocol: "udp"},
	}

	changes := analyzer.CompareFirewallRules(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
}

func TestAnalyzer_CompareFirewallRules_PermissiveRuleAdded(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []schema.Rule{}
	newCfg := []schema.Rule{
		{
			UUID: "uuid-1",
			Type: "pass",
			Source: schema.Source{
				Any: schema.StringPtr("true"),
			},
			Destination: schema.Destination{
				Any: schema.StringPtr("true"),
			},
		},
	}

	changes := analyzer.CompareFirewallRules(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, "high", changes[0].SecurityImpact)
}

func TestAnalyzer_CompareInterfaces_NoChanges(t *testing.T) {
	analyzer := NewAnalyzer()
	interfaces := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"wan": {IPAddr: "10.0.0.1", Subnet: "24"},
		},
	}

	changes := analyzer.CompareInterfaces(interfaces, interfaces)
	assert.Empty(t, changes)
}

func TestAnalyzer_CompareInterfaces_InterfaceAdded(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"wan": {IPAddr: "10.0.0.1"},
		},
	}
	newCfg := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"wan":  {IPAddr: "10.0.0.1"},
			"opt1": {IPAddr: "192.168.10.1", Descr: "DMZ"},
		},
	}

	changes := analyzer.CompareInterfaces(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.Contains(t, changes[0].Path, "opt1")
}

func TestAnalyzer_CompareInterfaces_InterfaceRemoved(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"wan":  {IPAddr: "10.0.0.1"},
			"opt1": {IPAddr: "192.168.10.1", Descr: "DMZ"},
		},
	}
	newCfg := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"wan": {IPAddr: "10.0.0.1"},
		},
	}

	changes := analyzer.CompareInterfaces(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)
	assert.Contains(t, changes[0].Path, "opt1")
}

func TestAnalyzer_CompareInterfaces_IPChanged(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"wan": {IPAddr: "10.0.0.1", Subnet: "24"},
		},
	}
	newCfg := &schema.Interfaces{
		Items: map[string]schema.Interface{
			"wan": {IPAddr: "10.0.0.2", Subnet: "24"},
		},
	}

	changes := analyzer.CompareInterfaces(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Equal(t, "interfaces.wan.ipaddr", changes[0].Path)
}

func TestAnalyzer_CompareVLANs_NoChanges(t *testing.T) {
	analyzer := NewAnalyzer()
	vlans := &schema.VLANs{
		VLAN: []schema.VLAN{
			{Vlanif: "vlan10", Tag: "10", If: "em0"},
		},
	}

	changes := analyzer.CompareVLANs(vlans, vlans)
	assert.Empty(t, changes)
}

func TestAnalyzer_CompareVLANs_VLANAdded(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &schema.VLANs{VLAN: []schema.VLAN{}}
	newCfg := &schema.VLANs{
		VLAN: []schema.VLAN{
			{Vlanif: "vlan10", Tag: "10", If: "em0", Descr: "Guest"},
		},
	}

	changes := analyzer.CompareVLANs(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.Contains(t, changes[0].Description, "vlan10")
}

func TestAnalyzer_CompareVLANs_VLANRemoved(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &schema.VLANs{
		VLAN: []schema.VLAN{
			{Vlanif: "vlan10", Tag: "10", If: "em0"},
		},
	}
	newCfg := &schema.VLANs{VLAN: []schema.VLAN{}}

	changes := analyzer.CompareVLANs(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)
}

func TestAnalyzer_CompareVLANs_TagChanged(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &schema.VLANs{
		VLAN: []schema.VLAN{
			{Vlanif: "vlan10", Tag: "10", If: "em0"},
		},
	}
	newCfg := &schema.VLANs{
		VLAN: []schema.VLAN{
			{Vlanif: "vlan10", Tag: "20", If: "em0"},
		},
	}

	changes := analyzer.CompareVLANs(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Contains(t, changes[0].Path, "tag")
}

func TestAnalyzer_CompareUsers_NoChanges(t *testing.T) {
	analyzer := NewAnalyzer()
	users := []schema.User{
		{Name: "admin", Scope: "system", Groupname: "admins"},
	}

	changes := analyzer.CompareUsers(users, users)
	assert.Empty(t, changes)
}

func TestAnalyzer_CompareUsers_UserAdded(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []schema.User{}
	newCfg := []schema.User{
		{Name: "admin", Scope: "system", Groupname: "admins", Descr: "Administrator"},
	}

	changes := analyzer.CompareUsers(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeAdded, changes[0].Type)
	assert.Equal(t, "medium", changes[0].SecurityImpact)
}

func TestAnalyzer_CompareUsers_UserRemoved(t *testing.T) {
	analyzer := NewAnalyzer()
	old := []schema.User{
		{Name: "olduser", Scope: "local", Groupname: "users"},
	}
	newCfg := []schema.User{}

	changes := analyzer.CompareUsers(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeRemoved, changes[0].Type)
	assert.Equal(t, "medium", changes[0].SecurityImpact)
}

func TestAnalyzer_CompareNAT_ModeChanged(t *testing.T) {
	analyzer := NewAnalyzer()
	old := &schema.Nat{
		Outbound: schema.Outbound{Mode: "automatic"},
	}
	newCfg := &schema.Nat{
		Outbound: schema.Outbound{Mode: "hybrid"},
	}

	changes := analyzer.CompareNAT(old, newCfg)

	assert.Len(t, changes, 1)
	assert.Equal(t, ChangeModified, changes[0].Type)
	assert.Equal(t, "medium", changes[0].SecurityImpact)
}

func TestFormatSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  schema.Source
		want string
	}{
		{
			name: "network only",
			src:  schema.Source{Network: "lan"},
			want: "lan",
		},
		{
			name: "address only",
			src:  schema.Source{Address: "10.0.0.1"},
			want: "10.0.0.1",
		},
		{
			name: "any via pointer",
			src:  schema.Source{Any: schema.StringPtr("")},
			want: "any",
		},
		{
			name: "empty source",
			src:  schema.Source{},
			want: "unknown",
		},
		{
			name: "negated network",
			src:  schema.Source{Network: "lan", Not: true},
			want: "!lan",
		},
		{
			name: "negated address with port",
			src:  schema.Source{Address: "192.168.1.0/24", Not: true, Port: "22"},
			want: "!192.168.1.0/24:22",
		},
		{
			name: "network with port",
			src:  schema.Source{Network: "wan", Port: "443"},
			want: "wan:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatSource(tt.src)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatDestination(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dst  schema.Destination
		want string
	}{
		{
			name: "network only",
			dst:  schema.Destination{Network: "wan"},
			want: "wan",
		},
		{
			name: "address only",
			dst:  schema.Destination{Address: "10.0.0.1"},
			want: "10.0.0.1",
		},
		{
			name: "any via pointer",
			dst:  schema.Destination{Any: schema.StringPtr("")},
			want: "any",
		},
		{
			name: "empty destination",
			dst:  schema.Destination{},
			want: "unknown",
		},
		{
			name: "negated with port",
			dst:  schema.Destination{Network: "lan", Not: true, Port: "80"},
			want: "!lan:80",
		},
		{
			name: "address with port",
			dst:  schema.Destination{Address: "10.0.0.5", Port: "8080"},
			want: "10.0.0.5:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatDestination(tt.dst)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule schema.Rule
		want string
	}{
		{
			name: "basic pass rule",
			rule: schema.Rule{
				Type:        "pass",
				Interface:   schema.InterfaceList{"wan"},
				Protocol:    "tcp",
				Source:      schema.Source{Network: "any"},
				Destination: schema.Destination{Network: "lan", Port: "443"},
			},
			want: "type=pass, if=wan, proto=tcp, src=any, dst=lan:443",
		},
		{
			name: "disabled rule",
			rule: schema.Rule{
				Type:        "block",
				Source:      schema.Source{Network: "any"},
				Destination: schema.Destination{Any: schema.StringPtr("")},
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
		rule schema.Rule
		want string
	}{
		{
			name: "with description",
			rule: schema.Rule{Descr: "Allow SSH"},
			want: "Allow SSH",
		},
		{
			name: "without description uses effective address",
			rule: schema.Rule{
				Type:        "pass",
				Source:      schema.Source{Address: "10.0.0.0/8"},
				Destination: schema.Destination{Any: schema.StringPtr("")},
			},
			want: "pass 10.0.0.0/8 → any",
		},
		{
			name: "empty addresses fall back to unknown",
			rule: schema.Rule{
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
	old := &schema.StaticRoutes{
		Route: []schema.StaticRoute{
			{Network: "10.0.0.0/8"},
		},
	}
	newCfg := &schema.StaticRoutes{
		Route: []schema.StaticRoute{
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
		rule schema.Rule
		want bool
	}{
		{
			name: "any/any pass rule via Any field",
			rule: schema.Rule{
				Type:        "pass",
				Source:      schema.Source{Any: ptrStr("")},
				Destination: schema.Destination{Any: ptrStr("")},
			},
			want: true,
		},
		{
			name: "any/any pass rule via Network field",
			rule: schema.Rule{
				Type:        "pass",
				Source:      schema.Source{Network: "any"},
				Destination: schema.Destination{Network: "any"},
			},
			want: true,
		},
		{
			name: "block rule is not permissive",
			rule: schema.Rule{
				Type:        "block",
				Source:      schema.Source{Any: ptrStr("")},
				Destination: schema.Destination{Any: ptrStr("")},
			},
			want: false,
		},
		{
			name: "specific source is not permissive",
			rule: schema.Rule{
				Type:        "pass",
				Source:      schema.Source{Network: "192.168.1.0/24"},
				Destination: schema.Destination{Any: ptrStr("")},
			},
			want: false,
		},
		{
			name: "any source via Address field",
			rule: schema.Rule{
				Type:        "pass",
				Source:      schema.Source{Address: "any"},
				Destination: schema.Destination{Network: "any"},
			},
			want: true,
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

func ptrStr(s string) *string {
	return &s
}
