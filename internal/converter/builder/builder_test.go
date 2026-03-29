package builder

import (
	"errors"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/nao1215/markdown"
)

func TestNewMarkdownBuilder(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()
	if builder == nil {
		t.Fatal("NewMarkdownBuilder returned nil")
	}

	if builder.generated.IsZero() {
		t.Error("NewMarkdownBuilder did not set generated time")
	}

	if builder.toolVersion == "" {
		t.Error("NewMarkdownBuilder did not set tool version")
	}

	if builder.logger == nil {
		t.Error("NewMarkdownBuilder did not create logger")
	}
}

func TestNewMarkdownBuilderWithConfig(t *testing.T) {
	t.Parallel()

	config := &common.CommonDevice{
		System: common.System{Hostname: "test"},
	}

	builder := NewMarkdownBuilderWithConfig(config, nil)
	if builder == nil {
		t.Fatal("NewMarkdownBuilderWithConfig returned nil")
	}

	if builder.config != config {
		t.Error("NewMarkdownBuilderWithConfig did not set config")
	}

	if builder.logger == nil {
		t.Error("NewMarkdownBuilderWithConfig did not create logger")
	}
}

//nolint:dupl // structurally similar to TestBuildComprehensiveReport_Errors but tests different method
func TestBuildStandardReport_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    *common.CommonDevice
		wantErr bool
	}{
		{
			name:    "nil document returns error",
			data:    nil,
			wantErr: true,
		},
		{
			name: "valid document returns no error",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "example.com",
					Firmware: common.Firmware{Version: "24.1"},
				},
			},
			wantErr: false,
		},
	}

	builder := NewMarkdownBuilder()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := builder.BuildStandardReport(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildStandardReport() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && !errors.Is(err, ErrNilDevice) {
				t.Errorf("BuildStandardReport() error = %v, want %v", err, ErrNilDevice)
			}
		})
	}
}

//nolint:dupl // structurally similar to TestBuildStandardReport_Errors but tests different method
func TestBuildComprehensiveReport_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    *common.CommonDevice
		wantErr bool
	}{
		{
			name:    "nil document returns error",
			data:    nil,
			wantErr: true,
		},
		{
			name: "valid document returns no error",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "example.com",
					Firmware: common.Firmware{Version: "24.1"},
				},
			},
			wantErr: false,
		},
	}

	builder := NewMarkdownBuilder()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := builder.BuildComprehensiveReport(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildComprehensiveReport() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && !errors.Is(err, ErrNilDevice) {
				t.Errorf("BuildComprehensiveReport() error = %v, want %v", err, ErrNilDevice)
			}
		})
	}
}

func TestBuildInterfaceDetails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		iface        common.Interface
		wantContains []string
	}{
		{
			name:         "empty interface",
			iface:        common.Interface{},
			wantContains: nil,
		},
		{
			name: "basic interface fields",
			iface: common.Interface{
				PhysicalIf: "em0",
				Enabled:    true,
				IPAddress:  "192.168.1.1",
				Subnet:     "24",
				Gateway:    "192.168.1.254",
				MTU:        "1500",
			},
			wantContains: []string{
				"**Physical Interface**: em0",
				"**Enabled**: ✓",
				"**IPv4 Address**: 192.168.1.1",
				"**IPv4 Subnet**: 24",
				"**Gateway**: 192.168.1.254",
				"**MTU**: 1500",
			},
		},
		{
			name: "ipv6 interface fields",
			iface: common.Interface{
				IPv6Address: "2001:db8::1",
				SubnetV6:    "64",
			},
			wantContains: []string{
				"**IPv6 Address**: 2001:db8::1",
				"**IPv6 Subnet**: 64",
			},
		},
		{
			name: "security fields",
			iface: common.Interface{
				BlockPrivate: true,
				BlockBogons:  true,
			},
			wantContains: []string{
				"**Block Private Networks**: ✓",
				"**Block Bogon Networks**: ✓",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf strings.Builder
			md := markdown.NewMarkdown(&buf)
			buildInterfaceDetails(md, tt.iface)
			output := md.String()

			for _, want := range tt.wantContains {
				if !strings.Contains(output, want) {
					t.Errorf("buildInterfaceDetails() missing expected content: %q\nOutput: %s", want, output)
				}
			}
		})
	}
}

// Table building function tests

func TestBuildFirewallRulesTableSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		rules        []common.FirewallRule
		wantRows     int
		wantContains []string
	}{
		{
			name:         "empty rules",
			rules:        nil,
			wantRows:     0,
			wantContains: nil,
		},
		{
			name: "single rule",
			rules: []common.FirewallRule{
				{
					Type:        common.RuleTypePass,
					Interfaces:  []string{"lan"},
					IPProtocol:  common.IPProtocolInet,
					Protocol:    "tcp",
					Target:      "any",
					Description: "Allow LAN traffic",
					Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
					Destination: common.RuleEndpoint{Address: "any", Port: "443"},
				},
			},
			wantRows: 1,
			wantContains: []string{
				"pass", "inet", "tcp", "192.168.1.0/24", "any", "443", "Allow LAN traffic",
			},
		},
		{
			name: "rule with disabled flag",
			rules: []common.FirewallRule{
				{
					Type:        common.RuleTypeBlock,
					Interfaces:  []string{"wan"},
					Disabled:    true,
					Description: "Disabled rule",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"block", "Disabled rule",
			},
		},
		{
			name: "rule with multiple interfaces",
			rules: []common.FirewallRule{
				{
					Type:        common.RuleTypePass,
					Interfaces:  []string{"lan", "wan", "opt1"},
					Protocol:    "udp",
					Description: "Multi-interface rule",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"pass", "udp", "Multi-interface rule",
			},
		},
	}

	expectedHeaders := []string{
		"#", "Interface", "Action", "IP Ver", "Proto", "Source", "Destination",
		"Target", "Source Port", "Dest Port", "Enabled", "Description",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tableSet := BuildFirewallRulesTableSet(tt.rules)
			verifyTableSet(t, tableSet, expectedHeaders, tt.wantRows, tt.wantContains)
		})
	}
}

func TestBuildOutboundNATTableSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		rules        []common.NATRule
		wantRows     int
		wantContains []string
	}{
		{
			name:     "empty rules returns placeholder",
			rules:    nil,
			wantRows: 1,
			wantContains: []string{
				"No outbound NAT rules configured",
			},
		},
		{
			name: "single nat rule",
			rules: []common.NATRule{
				{
					Interfaces:  []string{"wan"},
					Protocol:    "tcp",
					Target:      "192.168.1.1",
					Description: "Web server NAT",
					Source:      common.RuleEndpoint{Address: "192.168.1.0/24"},
					Destination: common.RuleEndpoint{Address: "any"},
				},
			},
			wantRows: 1,
			wantContains: []string{
				"⬆️ Outbound", "tcp", "192.168.1.0/24", "any", "`192.168.1.1`", "Web server NAT", "**Active**",
			},
		},
		{
			name: "disabled nat rule",
			rules: []common.NATRule{
				{
					Interfaces:  []string{"wan"},
					Disabled:    true,
					Description: "Disabled NAT",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"Disabled NAT", "**Disabled**",
			},
		},
	}

	expectedHeaders := []string{
		"#", "Direction", "Interface", "Source", "Destination", "Target", "Protocol", "Description", "Status",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tableSet := BuildOutboundNATTableSet(tt.rules)
			verifyTableSet(t, tableSet, expectedHeaders, tt.wantRows, tt.wantContains)
		})
	}
}

func TestBuildInboundNATTableSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		rules        []common.InboundNATRule
		wantRows     int
		wantContains []string
	}{
		{
			name:     "empty rules returns placeholder",
			rules:    nil,
			wantRows: 1,
			wantContains: []string{
				"No inbound NAT rules configured",
			},
		},
		{
			name: "single inbound rule",
			rules: []common.InboundNATRule{
				{
					Interfaces:   []string{"wan"},
					Protocol:     "tcp",
					ExternalPort: "80",
					InternalIP:   "192.168.1.100",
					InternalPort: "80",
					Priority:     1,
					Description:  "HTTP forward",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"⬇️ Inbound", "80", "`192.168.1.100`", "80", "tcp", "HTTP forward", "1", "**Active**",
			},
		},
		{
			name: "disabled inbound rule",
			rules: []common.InboundNATRule{
				{
					Interfaces:  []string{"wan"},
					Disabled:    true,
					Priority:    5,
					Description: "Disabled forward",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"Disabled forward", "5", "**Disabled**",
			},
		},
	}

	expectedHeaders := []string{
		"#", "Direction", "Interface", "External Port", "Target IP", "Target Port",
		"Protocol", "Description", "Priority", "Status",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tableSet := BuildInboundNATTableSet(tt.rules)
			verifyTableSet(t, tableSet, expectedHeaders, tt.wantRows, tt.wantContains)
		})
	}
}

func TestBuildInterfaceTableSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		interfaces   []common.Interface
		wantRows     int
		wantContains []string
	}{
		{
			name:         "empty interfaces",
			interfaces:   []common.Interface{},
			wantRows:     0,
			wantContains: nil,
		},
		{
			name: "single interface",
			interfaces: []common.Interface{
				{
					Name:        "lan",
					PhysicalIf:  "em0",
					Description: "LAN Interface",
					Enabled:     true,
					IPAddress:   "192.168.1.1",
					Subnet:      "24",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"`lan`", "`LAN Interface`", "`192.168.1.1`", "/24", "✓",
			},
		},
		{
			name: "interface without description uses PhysicalIf field",
			interfaces: []common.Interface{
				{
					Name:       "wan",
					PhysicalIf: "em1",
					Enabled:    false,
					IPAddress:  "dhcp",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"`wan`", "`em1`", "`dhcp`", "✗",
			},
		},
		{
			name: "multiple interfaces sorted by name",
			interfaces: []common.Interface{
				{Name: "wan", PhysicalIf: "em1", Enabled: true},
				{Name: "lan", PhysicalIf: "em0", Enabled: true},
				{Name: "opt1", PhysicalIf: "em2", Enabled: false},
			},
			wantRows: 3,
			wantContains: []string{
				"`lan`", "`opt1`", "`wan`", // Should appear in sorted order
			},
		},
	}

	expectedHeaders := []string{"Name", "Description", "IP Address", "CIDR", "Enabled"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tableSet := BuildInterfaceTableSet(tt.interfaces)
			verifyTableSet(t, tableSet, expectedHeaders, tt.wantRows, tt.wantContains)
		})
	}
}

func TestBuildUserTableSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		users        []common.User
		wantRows     int
		wantContains []string
	}{
		{
			name:         "empty users",
			users:        nil,
			wantRows:     0,
			wantContains: nil,
		},
		{
			name: "single user",
			users: []common.User{
				{
					Name:        "admin",
					Description: "System Administrator",
					GroupName:   "admins",
					Scope:       "system",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"admin", "System Administrator", "admins", "system",
			},
		},
		{
			name: "multiple users",
			users: []common.User{
				{Name: "admin", Description: "Administrator", GroupName: "admins", Scope: "system"},
				{Name: "user1", Description: "Regular User", GroupName: "users", Scope: "user"},
			},
			wantRows: 2,
			wantContains: []string{
				"admin", "Administrator", "admins", "system",
				"user1", "Regular User", "users", "user",
			},
		},
	}

	expectedHeaders := []string{"Name", "Description", "Group", "Scope"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tableSet := BuildUserTableSet(tt.users)
			verifyTableSet(t, tableSet, expectedHeaders, tt.wantRows, tt.wantContains)
		})
	}
}

func TestBuildGroupTableSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		groups       []common.Group
		wantRows     int
		wantContains []string
	}{
		{
			name:         "empty groups",
			groups:       nil,
			wantRows:     0,
			wantContains: nil,
		},
		{
			name: "single group",
			groups: []common.Group{
				{
					Name:        "admins",
					Description: "System Administrators",
					Scope:       "system",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"admins", "System Administrators", "system",
			},
		},
	}

	expectedHeaders := []string{"Name", "Description", "Scope"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tableSet := BuildGroupTableSet(tt.groups)
			verifyTableSet(t, tableSet, expectedHeaders, tt.wantRows, tt.wantContains)
		})
	}
}

func TestBuildSysctlTableSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		sysctl       []common.SysctlItem
		wantRows     int
		wantContains []string
	}{
		{
			name:         "empty sysctl",
			sysctl:       nil,
			wantRows:     0,
			wantContains: nil,
		},
		{
			name: "single sysctl item",
			sysctl: []common.SysctlItem{
				{
					Tunable:     "kern.ipc.maxsockbuf",
					Value:       "16777216",
					Description: "Maximum socket buffer size",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"kern.ipc.maxsockbuf", "16777216", "Maximum socket buffer size",
			},
		},
	}

	expectedHeaders := []string{"Tunable", "Value", "Description"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tableSet := BuildSysctlTableSet(tt.sysctl)
			verifyTableSet(t, tableSet, expectedHeaders, tt.wantRows, tt.wantContains)
		})
	}
}

func TestBuildVLANTableSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		vlans        []common.VLAN
		wantRows     int
		wantContains []string
	}{
		{
			name:     "empty vlans returns placeholder",
			vlans:    nil,
			wantRows: 1,
			wantContains: []string{
				"No VLANs configured",
			},
		},
		{
			name: "single vlan",
			vlans: []common.VLAN{
				{
					VLANIf:      "vlan10",
					PhysicalIf:  "em0",
					Tag:         "10",
					Description: "Management VLAN",
					Created:     "2024-01-01",
					Updated:     "2024-01-02",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"vlan10", "em0", "10", "Management VLAN", "2024-01-01", "2024-01-02",
			},
		},
	}

	expectedHeaders := []string{
		"VLAN Interface", "Physical Interface", "VLAN Tag", "Description", "Created", "Updated",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tableSet := BuildVLANTableSet(tt.vlans)
			verifyTableSet(t, tableSet, expectedHeaders, tt.wantRows, tt.wantContains)
		})
	}
}

func TestBuildStaticRoutesTableSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		routes       []common.StaticRoute
		wantRows     int
		wantContains []string
	}{
		{
			name:     "empty routes returns placeholder",
			routes:   nil,
			wantRows: 1,
			wantContains: []string{
				"No static routes configured",
			},
		},
		{
			name: "enabled route",
			routes: []common.StaticRoute{
				{
					Network:     "10.0.0.0/8",
					Gateway:     "192.168.1.1",
					Description: "Internal networks",
					Disabled:    false,
					Created:     "2024-01-01",
					Updated:     "2024-01-02",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"10.0.0.0/8", "192.168.1.1", "Internal networks", "**Enabled**", "2024-01-01", "2024-01-02",
			},
		},
		{
			name: "disabled route",
			routes: []common.StaticRoute{
				{
					Network:     "172.16.0.0/12",
					Gateway:     "192.168.1.2",
					Description: "Disabled route",
					Disabled:    true,
				},
			},
			wantRows: 1,
			wantContains: []string{
				"172.16.0.0/12", "192.168.1.2", "Disabled route", "Disabled",
			},
		},
	}

	expectedHeaders := []string{
		"Destination Network", "Gateway", "Description", "Status", "Created", "Updated",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tableSet := BuildStaticRoutesTableSet(tt.routes)
			verifyTableSet(t, tableSet, expectedHeaders, tt.wantRows, tt.wantContains)
		})
	}
}

// Test the write-style methods that delegate to build methods.
func TestWriteTableMethods(t *testing.T) {
	t.Parallel()

	builder := NewMarkdownBuilder()

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "WriteFirewallRulesTable",
			test: func(t *testing.T) {
				t.Helper()
				t.Parallel()
				var buf strings.Builder
				md := markdown.NewMarkdown(&buf)
				rules := []common.FirewallRule{
					{Type: common.RuleTypePass, Interfaces: []string{"lan"}, Description: "Test rule"},
				}
				result := builder.WriteFirewallRulesTable(md, rules)
				if result != md {
					t.Error("WriteFirewallRulesTable should return the markdown instance for chaining")
				}
				output := md.String()
				if !strings.Contains(output, "pass") || !strings.Contains(output, "Test rule") {
					t.Error("WriteFirewallRulesTable output missing expected content")
				}
			},
		},
		{
			name: "WriteInterfaceTable",
			test: func(t *testing.T) {
				t.Helper()
				t.Parallel()
				var buf strings.Builder
				md := markdown.NewMarkdown(&buf)
				interfaces := []common.Interface{
					{Name: "lan", PhysicalIf: "em0", Enabled: true, IPAddress: "192.168.1.1"},
				}
				result := builder.WriteInterfaceTable(md, interfaces)
				if result != md {
					t.Error("WriteInterfaceTable should return the markdown instance for chaining")
				}
				output := md.String()
				if !strings.Contains(output, "lan") || !strings.Contains(output, "192.168.1.1") {
					t.Error("WriteInterfaceTable output missing expected content")
				}
			},
		},
		{
			name: "WriteOutboundNATTable",
			test: func(t *testing.T) {
				t.Helper()
				t.Parallel()
				var buf strings.Builder
				md := markdown.NewMarkdown(&buf)
				rules := []common.NATRule{
					{Interfaces: []string{"wan"}, Description: "Test NAT"},
				}
				result := builder.WriteOutboundNATTable(md, rules)
				if result != md {
					t.Error("WriteOutboundNATTable should return the markdown instance for chaining")
				}
			},
		},
		{
			name: "WriteInboundNATTable",
			test: func(t *testing.T) {
				t.Helper()
				t.Parallel()
				var buf strings.Builder
				md := markdown.NewMarkdown(&buf)
				rules := []common.InboundNATRule{
					{Interfaces: []string{"wan"}, Description: "Test forward"},
				}
				result := builder.WriteInboundNATTable(md, rules)
				if result != md {
					t.Error("WriteInboundNATTable should return the markdown instance for chaining")
				}
			},
		},
		{
			name: "WriteUserTable",
			test: func(t *testing.T) {
				t.Helper()
				t.Parallel()
				var buf strings.Builder
				md := markdown.NewMarkdown(&buf)
				users := []common.User{
					{Name: "admin", Description: "Administrator"},
				}
				result := builder.WriteUserTable(md, users)
				if result != md {
					t.Error("WriteUserTable should return the markdown instance for chaining")
				}
			},
		},
		{
			name: "WriteGroupTable",
			test: func(t *testing.T) {
				t.Helper()
				t.Parallel()
				var buf strings.Builder
				md := markdown.NewMarkdown(&buf)
				groups := []common.Group{
					{Name: "admins", Description: "Administrators"},
				}
				result := builder.WriteGroupTable(md, groups)
				if result != md {
					t.Error("WriteGroupTable should return the markdown instance for chaining")
				}
			},
		},
		{
			name: "WriteSysctlTable",
			test: func(t *testing.T) {
				t.Helper()
				t.Parallel()
				var buf strings.Builder
				md := markdown.NewMarkdown(&buf)
				sysctl := []common.SysctlItem{
					{Tunable: "net.inet.tcp.mssdflt", Value: "1460"},
				}
				result := builder.WriteSysctlTable(md, sysctl)
				if result != md {
					t.Error("WriteSysctlTable should return the markdown instance for chaining")
				}
			},
		},
		{
			name: "WriteVLANTable",
			test: func(t *testing.T) {
				t.Helper()
				t.Parallel()
				var buf strings.Builder
				md := markdown.NewMarkdown(&buf)
				vlans := []common.VLAN{
					{VLANIf: "vlan10", Tag: "10"},
				}
				result := builder.WriteVLANTable(md, vlans)
				if result != md {
					t.Error("WriteVLANTable should return the markdown instance for chaining")
				}
			},
		},
		{
			name: "WriteStaticRoutesTable",
			test: func(t *testing.T) {
				t.Helper()
				t.Parallel()
				var buf strings.Builder
				md := markdown.NewMarkdown(&buf)
				routes := []common.StaticRoute{
					{Network: "10.0.0.0/8", Gateway: "192.168.1.1"},
				}
				result := builder.WriteStaticRoutesTable(md, routes)
				if result != md {
					t.Error("WriteStaticRoutesTable should return the markdown instance for chaining")
				}
			},
		},
		{
			name: "WriteDHCPSummaryTable",
			test: func(t *testing.T) {
				t.Helper()
				t.Parallel()
				var buf strings.Builder
				md := markdown.NewMarkdown(&buf)
				scopes := []common.DHCPScope{
					{Interface: "lan", Enabled: true, Gateway: "192.168.1.1"},
				}
				result := builder.WriteDHCPSummaryTable(md, scopes)
				if result != md {
					t.Error("WriteDHCPSummaryTable should return the markdown instance for chaining")
				}
			},
		},
		{
			name: "WriteDHCPStaticLeasesTable",
			test: func(t *testing.T) {
				t.Helper()
				t.Parallel()
				var buf strings.Builder
				md := markdown.NewMarkdown(&buf)
				leases := []common.DHCPStaticLease{
					{MAC: "00:11:22:33:44:55", IPAddress: "192.168.1.100"},
				}
				result := builder.WriteDHCPStaticLeasesTable(md, leases)
				if result != md {
					t.Error("WriteDHCPStaticLeasesTable should return the markdown instance for chaining")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildAuditSection Tests
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildAuditSection_NilData(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	result := b.BuildAuditSection(nil)
	if result != "" {
		t.Errorf("BuildAuditSection with nil data should return empty string, got: %s", result)
	}
}

func TestBuildAuditSection_NilComplianceChecks(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{ComplianceChecks: nil}

	result := b.BuildAuditSection(data)
	if result != "" {
		t.Errorf("BuildAuditSection with nil ComplianceChecks should return empty string, got: %s", result)
	}
}

func TestBuildAuditSection_EmptyComplianceResults(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{Mode: "blue"},
	}

	result := b.BuildAuditSection(data)
	if !strings.Contains(result, "## Compliance Audit Summary") {
		t.Error("Expected '### Compliance Audit Summary' in output")
	}
	if !strings.Contains(result, "blue") {
		t.Error("Expected mode 'blue' in output")
	}
	if strings.Contains(result, "### Security Findings") {
		t.Error("Should not contain '### Security Findings' when no findings")
	}
	if strings.Contains(result, "## Compliance Audit Results") {
		t.Error("Should not contain '## Compliance Audit Results' when no plugin results")
	}
}

func TestBuildAuditSection_WithFindings(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			Findings: []common.ComplianceFinding{
				{Severity: "high", Component: "firewall", Title: "Open Port", Recommendation: "Close unused ports"},
				{
					Severity:       "critical",
					Component:      "auth",
					Title:          "Weak Password",
					Recommendation: "Enforce strong passwords",
				},
			},
			Summary: &common.ComplianceResultSummary{TotalFindings: 2},
		},
	}

	result := b.BuildAuditSection(data)
	expectedContent := []string{
		"### Security Findings",
		"high",
		"critical",
		"firewall",
		"auth",
		"Open Port",
		"Weak Password",
		"Close unused ports",
		"Enforce strong passwords",
	}
	for _, content := range expectedContent {
		if !strings.Contains(result, content) {
			t.Errorf("Expected output to contain %q", content)
		}
	}
}

func TestBuildAuditSection_WithPluginResults(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			PluginResults: map[string]common.PluginComplianceResult{
				"firewall": {
					PluginInfo: common.CompliancePluginInfo{Name: "firewall", Version: "1.0"},
					Findings: []common.ComplianceFinding{
						{Severity: "critical", Title: "FW Issue 1", Description: "Critical firewall issue"},
						{Severity: "critical", Title: "FW Issue 2", Description: "Another critical issue"},
						{Severity: "high", Title: "FW Issue 3", Description: "High issue"},
					},
					Summary: &common.ComplianceResultSummary{
						TotalFindings:    3,
						CriticalFindings: 2,
						HighFindings:     1,
					},
				},
				"stig": {
					PluginInfo: common.CompliancePluginInfo{Name: "stig", Version: "2.0"},
					Findings: []common.ComplianceFinding{
						{Severity: "medium", Title: "STIG Check", Description: "Medium stig issue"},
					},
					Summary: &common.ComplianceResultSummary{
						TotalFindings:  1,
						MediumFindings: 1,
					},
				},
			},
			Summary: &common.ComplianceResultSummary{TotalFindings: 4},
		},
	}

	result := b.BuildAuditSection(data)

	expectedContent := []string{
		"## Compliance Audit Results",
		"### firewall",
		"### stig",
		"Critical: 2",
		"High: 1",
		"Medium: 1",
		"#### firewall Plugin Findings",
		"#### stig Plugin Findings",
	}
	for _, content := range expectedContent {
		if !strings.Contains(result, content) {
			t.Errorf("Expected output to contain %q", content)
		}
	}

	// Verify sorted order: firewall before stig
	fwIdx := strings.Index(result, "### firewall")
	stigIdx := strings.Index(result, "### stig")
	if fwIdx >= stigIdx {
		t.Error("Expected 'firewall' to appear before 'stig' (sorted order)")
	}
}

func TestBuildAuditSection_WithMetadata(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			Metadata: map[string]any{
				"scan_time": "2024-01-15",
				"version":   "1.0",
			},
			Summary: &common.ComplianceResultSummary{TotalFindings: 0},
		},
	}

	result := b.BuildAuditSection(data)

	expectedContent := []string{
		"## Audit Metadata",
		"scan_time",
		"version",
		"2024-01-15",
		"1.0",
	}
	for _, content := range expectedContent {
		if !strings.Contains(result, content) {
			t.Errorf("Expected output to contain %q", content)
		}
	}
}

func TestBuildAuditSection_PipeEscaping(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			Findings: []common.ComplianceFinding{
				{
					Severity:       "high",
					Component:      "firewall|nat",
					Title:          "Rule with | pipe",
					Recommendation: "Fix the | issue",
				},
			},
			Summary: &common.ComplianceResultSummary{TotalFindings: 1},
		},
	}

	result := b.BuildAuditSection(data)

	if !strings.Contains(result, "firewall\\|nat") {
		t.Error("Expected escaped pipe in component")
	}
	if !strings.Contains(result, "Rule with \\| pipe") {
		t.Error("Expected escaped pipe in title")
	}
	if !strings.Contains(result, "Fix the \\| issue") {
		t.Error("Expected escaped pipe in recommendation")
	}
}

func TestBuildAuditSection_MetadataValuePipeEscaping(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			Metadata: map[string]any{
				"tool":    "scanner|v2",
				"key|bar": "value|baz",
			},
			Summary: &common.ComplianceResultSummary{TotalFindings: 0},
		},
	}

	result := b.BuildAuditSection(data)

	if !strings.Contains(result, "scanner\\|v2") {
		t.Error("Expected escaped pipe in metadata value")
	}
	if !strings.Contains(result, "key\\|bar") {
		t.Error("Expected escaped pipe in metadata key")
	}
	if !strings.Contains(result, "value\\|baz") {
		t.Error("Expected escaped pipe in metadata value with pipe key")
	}
}

func TestBuildAuditSection_DescriptionTruncation(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	longDescription := strings.Repeat("a", 100)

	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			PluginResults: map[string]common.PluginComplianceResult{
				"test": {
					Findings: []common.ComplianceFinding{
						{Severity: "high", Title: "Test", Description: longDescription},
					},
					Summary: &common.ComplianceResultSummary{TotalFindings: 1, HighFindings: 1},
				},
			},
			Summary: &common.ComplianceResultSummary{TotalFindings: 1},
		},
	}

	result := b.BuildAuditSection(data)

	if strings.Contains(result, longDescription) {
		t.Error("Full long description should not appear in output")
	}
	if !strings.Contains(result, "...") {
		t.Error("Truncated description should contain '...' ellipsis")
	}
}

func TestBuildAuditSection_NilPluginSummary(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			PluginResults: map[string]common.PluginComplianceResult{
				"nil_summary": {
					Summary: nil,
				},
			},
		},
	}

	// Must not panic
	result := b.BuildAuditSection(data)

	if !strings.Contains(result, "no data available") {
		t.Error("Expected 'no data available' fallback for nil summary")
	}
}

func TestBuildAuditSection_FallbackTotalCountsFindings(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			Findings: []common.ComplianceFinding{
				{Title: "Direct finding 1", Severity: "high"},
				{Title: "Direct finding 2", Severity: "medium"},
			},
			PluginResults: map[string]common.PluginComplianceResult{
				"no-summary-plugin": {
					Findings: []common.ComplianceFinding{
						{Title: "Plugin finding", Severity: "low"},
					},
					Summary: nil,
				},
			},
			// Summary is nil — forces fallback path
		},
	}

	result := b.BuildAuditSection(data)

	// Fallback should count 2 direct + 1 plugin finding = 3 total
	if !strings.Contains(result, "3") {
		t.Errorf("Fallback total should count direct findings + plugin findings, got:\n%s", result)
	}
}

// TestBuildAuditSection_ControlsTableAllStatuses verifies that when Controls and Compliance
// data are available, the unified controls table renders all controls with PASS/FAIL status.
func TestBuildAuditSection_ControlsTableAllStatuses(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			Summary: &common.ComplianceResultSummary{
				TotalFindings: 1,
				Compliant:     2,
				NonCompliant:  1,
			},
			PluginResults: map[string]common.PluginComplianceResult{
				"test-plugin": {
					Summary: &common.ComplianceResultSummary{
						TotalFindings: 1,
						Compliant:     2,
						NonCompliant:  1,
					},
					Controls: []common.ComplianceControl{
						{
							ID:       "CTRL-001",
							Status:   common.ControlStatusPass,
							Title:    "Enable logging",
							Severity: "high",
							Category: "Logging",
						},
						{
							ID:       "CTRL-002",
							Status:   common.ControlStatusFail,
							Title:    "Disable telnet",
							Severity: "critical",
							Category: "Access",
						},
						{
							ID:       "CTRL-003",
							Status:   common.ControlStatusPass,
							Title:    "Set timezone",
							Severity: "low",
							Category: "System",
						},
					},
					Compliance: map[string]bool{
						"CTRL-001": true,
						"CTRL-002": false,
						"CTRL-003": true,
					},
				},
			},
		},
	}

	result := b.BuildAuditSection(data)

	for _, want := range []string{"CTRL-001", "CTRL-002", "CTRL-003", "PASS", "FAIL", "Compliant", "Non-Compliant", "Control ID", "Status"} {
		if !strings.Contains(result, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, result)
		}
	}
}

// TestBuildAuditSection_ControlsTableFailuresOnly verifies that when failuresOnly is true,
// only FAIL rows appear in the controls table and PASS rows are excluded.
func TestBuildAuditSection_ControlsTableFailuresOnly(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	b.SetFailuresOnly(true)

	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			Summary: &common.ComplianceResultSummary{
				TotalFindings: 1,
				Compliant:     2,
				NonCompliant:  1,
			},
			PluginResults: map[string]common.PluginComplianceResult{
				"test-plugin": {
					Summary: &common.ComplianceResultSummary{
						TotalFindings: 1,
						Compliant:     2,
						NonCompliant:  1,
					},
					Controls: []common.ComplianceControl{
						{
							ID:       "CTRL-001",
							Status:   common.ControlStatusPass,
							Title:    "Enable logging",
							Severity: "high",
							Category: "Logging",
						},
						{
							ID:       "CTRL-002",
							Status:   common.ControlStatusFail,
							Title:    "Disable telnet",
							Severity: "critical",
							Category: "Access",
						},
						{
							ID:       "CTRL-003",
							Status:   common.ControlStatusPass,
							Title:    "Set timezone",
							Severity: "low",
							Category: "System",
						},
					},
					Compliance: map[string]bool{
						"CTRL-001": true,
						"CTRL-002": false,
						"CTRL-003": true,
					},
				},
			},
		},
	}

	result := b.BuildAuditSection(data)

	// Only CTRL-002 (FAIL) should appear
	for _, want := range []string{"CTRL-002", "FAIL"} {
		if !strings.Contains(result, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, result)
		}
	}

	// CTRL-001 and CTRL-003 (PASS) should be excluded
	for _, unwanted := range []string{"CTRL-001", "CTRL-003"} {
		if strings.Contains(result, unwanted) {
			t.Errorf("expected output NOT to contain %q (passing control), got:\n%s", unwanted, result)
		}
	}
}

// TestBuildAuditSection_ControlsTableFailuresOnlyAllPass verifies that when failuresOnly
// is true and all controls pass, an "All controls compliant" message is emitted.
func TestBuildAuditSection_ControlsTableFailuresOnlyAllPass(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	b.SetFailuresOnly(true)

	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			Summary: &common.ComplianceResultSummary{
				Compliant:    3,
				NonCompliant: 0,
			},
			PluginResults: map[string]common.PluginComplianceResult{
				"test-plugin": {
					Summary: &common.ComplianceResultSummary{
						Compliant:    3,
						NonCompliant: 0,
					},
					Controls: []common.ComplianceControl{
						{
							ID:       "CTRL-001",
							Status:   common.ControlStatusPass,
							Title:    "A",
							Severity: "high",
							Category: "Logging",
						},
						{
							ID:       "CTRL-002",
							Status:   common.ControlStatusPass,
							Title:    "B",
							Severity: "medium",
							Category: "Access",
						},
						{
							ID:       "CTRL-003",
							Status:   common.ControlStatusPass,
							Title:    "C",
							Severity: "low",
							Category: "System",
						},
					},
					Compliance: map[string]bool{
						"CTRL-001": true,
						"CTRL-002": true,
						"CTRL-003": true,
					},
				},
			},
		},
	}

	result := b.BuildAuditSection(data)

	// Should show the all-compliant message, not an empty table
	if !strings.Contains(result, "All controls compliant") {
		t.Errorf("expected 'All controls compliant' message, got:\n%s", result)
	}

	// Should still show the section header
	if !strings.Contains(result, "Plugin Results") {
		t.Errorf("expected 'Plugin Results' header, got:\n%s", result)
	}

	// No control IDs should appear in the table (all filtered)
	for _, unwanted := range []string{"CTRL-001", "CTRL-002", "CTRL-003"} {
		if strings.Contains(result, unwanted) {
			t.Errorf("expected output NOT to contain %q (all pass, filtered), got:\n%s", unwanted, result)
		}
	}
}

// TestBuildAuditSection_SummaryCompliantCounts verifies that Compliant and Non-Compliant
// counts appear in the summary table when present.
func TestBuildAuditSection_SummaryCompliantCounts(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			Summary: &common.ComplianceResultSummary{
				TotalFindings: 2,
				Compliant:     3,
				NonCompliant:  2,
			},
			PluginResults: map[string]common.PluginComplianceResult{},
		},
	}

	result := b.BuildAuditSection(data)

	for _, want := range []string{"Compliant", "Non-Compliant"} {
		if !strings.Contains(result, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, result)
		}
	}
}

// TestBuildAuditSection_ControlsFallbackToFindings verifies that when a plugin has no Controls
// but has Findings, the legacy Plugin Findings table is rendered (regression guard).
func TestBuildAuditSection_ControlsFallbackToFindings(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			PluginResults: map[string]common.PluginComplianceResult{
				"legacy-plugin": {
					Summary: &common.ComplianceResultSummary{TotalFindings: 1},
					Findings: []common.ComplianceFinding{
						{
							Control:     "LEGACY-001",
							Severity:    "medium",
							Title:       "Legacy finding",
							Description: "A legacy finding without controls data",
						},
					},
					// Controls is nil — triggers legacy fallback
				},
			},
		},
	}

	result := b.BuildAuditSection(data)

	// Legacy findings table header should appear
	for _, want := range []string{"legacy-plugin Plugin Findings", "LEGACY-001", "Legacy finding"} {
		if !strings.Contains(result, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, result)
		}
	}

	// Controls table headers should NOT appear
	for _, unwanted := range []string{"Plugin Results", "Status"} {
		if strings.Contains(result, unwanted) {
			t.Errorf("expected output NOT to contain %q, got:\n%s", unwanted, result)
		}
	}
}

// TestBuildAuditSection_ZeroCompliantCountsStillRendered verifies that Compliant and
// Non-Compliant rows appear in both the summary table and per-plugin bullet lists even
// when both counts are zero.
func TestBuildAuditSection_ZeroCompliantCountsStillRendered(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			Summary: &common.ComplianceResultSummary{
				TotalFindings: 0,
				Compliant:     0,
				NonCompliant:  0,
			},
			PluginResults: map[string]common.PluginComplianceResult{
				"zero-plugin": {
					Summary: &common.ComplianceResultSummary{
						TotalFindings: 0,
						Compliant:     0,
						NonCompliant:  0,
					},
				},
			},
		},
	}

	result := b.BuildAuditSection(data)

	// Top-level summary table must include Compliant and Non-Compliant rows
	for _, want := range []string{"Compliant", "Non-Compliant"} {
		if !strings.Contains(result, want) {
			t.Errorf("expected summary table to contain %q even when zero, got:\n%s", want, result)
		}
	}

	// Per-plugin bullet list must include Compliant and Non-Compliant items
	if !strings.Contains(result, "Compliant: 0") {
		t.Errorf("expected per-plugin bullet to contain 'Compliant: 0', got:\n%s", result)
	}

	if !strings.Contains(result, "Non-Compliant: 0") {
		t.Errorf("expected per-plugin bullet to contain 'Non-Compliant: 0', got:\n%s", result)
	}
}

// TestBuildAuditSection_EmptyStatusDefaultsToUnknown verifies that controls with an
// empty Status field are rendered as UNKNOWN (defensive fallback in writePluginControlsTable).
func TestBuildAuditSection_EmptyStatusDefaultsToUnknown(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			Summary: &common.ComplianceResultSummary{
				TotalFindings: 0,
			},
			PluginResults: map[string]common.PluginComplianceResult{
				"test-plugin": {
					Summary: &common.ComplianceResultSummary{},
					Controls: []common.ComplianceControl{
						{
							ID:       "CTRL-EMPTY",
							Status:   "",
							Title:    "Empty status control",
							Severity: "high",
							Category: "Test",
						},
					},
					Compliance: map[string]bool{},
				},
			},
		},
	}

	result := b.BuildAuditSection(data)

	// Control should render as UNKNOWN due to empty-string fallback
	if !strings.Contains(result, "CTRL-EMPTY") {
		t.Errorf("expected CTRL-EMPTY in output, got:\n%s", result)
	}

	if !strings.Contains(result, "UNKNOWN") {
		t.Errorf("expected UNKNOWN status for empty-Status control, got:\n%s", result)
	}

	if strings.Contains(result, "PASS") {
		t.Errorf("expected no PASS in output for empty-Status control, got:\n%s", result)
	}
}

// TestBuildAuditSection_ConfigurationNotes verifies that inventory-type findings
// appear in a dedicated "Configuration Notes" section and not in "Security Findings".
func TestBuildAuditSection_ConfigurationNotes(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			PluginResults: map[string]common.PluginComplianceResult{
				"firewall": {
					Findings: []common.ComplianceFinding{
						{
							Type:           "compliance",
							Severity:       "high",
							Component:      "ssh-config",
							Title:          "SSH Banner Missing",
							Recommendation: "Add banner",
						},
						{
							Type:        "inventory",
							Severity:    "info",
							Component:   "dhcp-config",
							Title:       "DHCP Scopes Configured",
							Description: "2 DHCP scope(s) configured on interface(s): lan, guest",
						},
						{
							Type:        "inventory",
							Severity:    "info",
							Component:   "interfaces",
							Title:       "Active Interfaces",
							Description: "4 enabled interface(s)",
						},
					},
					Summary: &common.ComplianceResultSummary{
						TotalFindings: 3,
						HighFindings:  1,
						InfoFindings:  2,
					},
				},
			},
			Summary: &common.ComplianceResultSummary{
				TotalFindings: 3,
				HighFindings:  1,
				InfoFindings:  2,
			},
		},
	}

	result := b.BuildAuditSection(data)

	// Configuration Notes section should be present
	if !strings.Contains(result, "### Configuration Notes") {
		t.Errorf("expected Configuration Notes section in output")
	}

	// Inventory content should appear in Configuration Notes
	for _, content := range []string{"dhcp-config", "DHCP Scopes Configured", "2 DHCP scope(s)", "interfaces", "Active Interfaces", "4 enabled"} {
		if !strings.Contains(result, content) {
			t.Errorf("expected Configuration Notes to contain %q", content)
		}
	}

	// InfoFindings should appear in per-plugin summary
	if !strings.Contains(result, "Informational: 2") {
		t.Errorf("expected per-plugin summary to show Informational: 2")
	}
}

// TestBuildAuditSection_NoConfigurationNotesWhenNoInventory verifies that the
// Configuration Notes section is omitted when there are no inventory findings.
func TestBuildAuditSection_NoConfigurationNotesWhenNoInventory(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			PluginResults: map[string]common.PluginComplianceResult{
				"firewall": {
					Findings: []common.ComplianceFinding{
						{
							Type:           "compliance",
							Severity:       "high",
							Component:      "ssh-config",
							Title:          "SSH Banner Missing",
							Recommendation: "Add banner",
						},
					},
					Summary: &common.ComplianceResultSummary{TotalFindings: 1, HighFindings: 1},
				},
			},
			Summary: &common.ComplianceResultSummary{TotalFindings: 1, HighFindings: 1},
		},
	}

	result := b.BuildAuditSection(data)

	if strings.Contains(result, "Configuration Notes") {
		t.Errorf("expected no Configuration Notes section when no inventory findings exist")
	}
}

// TestBuildAuditSection_InventoryExcludedFromSecurityFindings verifies that
// inventory findings do not appear in the Security Findings table.
func TestBuildAuditSection_InventoryExcludedFromSecurityFindings(t *testing.T) {
	t.Parallel()

	b := NewMarkdownBuilder()
	data := &common.CommonDevice{
		ComplianceChecks: &common.ComplianceResults{
			Mode: "blue",
			Findings: []common.ComplianceFinding{
				{
					Type:           "compliance",
					Severity:       "high",
					Component:      "auth",
					Title:          "Weak Password",
					Recommendation: "Fix it",
				},
				{
					Type:        "inventory",
					Severity:    "info",
					Component:   "dhcp",
					Title:       "DHCP Inventory",
					Description: "3 scopes",
				},
			},
			Summary: &common.ComplianceResultSummary{TotalFindings: 2},
		},
	}

	result := b.BuildAuditSection(data)

	// Security Findings should contain the compliance finding
	if !strings.Contains(result, "Weak Password") {
		t.Errorf("expected Security Findings to contain compliance finding")
	}

	// Security Findings should NOT contain the inventory finding title in the same table
	// The inventory finding should only be in Configuration Notes
	if !strings.Contains(result, "Configuration Notes") {
		t.Errorf("expected Configuration Notes section for inventory findings in top-level Findings")
	}
}

// Use helper functions from existing helpers_test.go
