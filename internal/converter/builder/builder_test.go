package builder

import (
	"errors"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
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

	config := &model.OpnSenseDocument{
		System: model.System{Hostname: "test"},
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

func TestBuildStandardReport_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    *model.OpnSenseDocument
		wantErr bool
	}{
		{
			name:    "nil document returns error",
			data:    nil,
			wantErr: true,
		},
		{
			name: "valid document returns no error",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
					Domain:   "example.com",
					Firmware: model.Firmware{Version: "24.1"},
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

			if tt.wantErr && !errors.Is(err, ErrNilOpnSenseDocument) {
				t.Errorf("BuildStandardReport() error = %v, want %v", err, ErrNilOpnSenseDocument)
			}
		})
	}
}

//nolint:dupl
func TestBuildComprehensiveReport_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    *model.OpnSenseDocument
		wantErr bool
	}{
		{
			name:    "nil document returns error",
			data:    nil,
			wantErr: true,
		},
		{
			name: "valid document returns no error",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
					Domain:   "example.com",
					Firmware: model.Firmware{Version: "24.1"},
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

			if tt.wantErr && !errors.Is(err, ErrNilOpnSenseDocument) {
				t.Errorf("BuildComprehensiveReport() error = %v, want %v", err, ErrNilOpnSenseDocument)
			}
		})
	}
}

func TestBuildInterfaceDetails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		iface        model.Interface
		wantContains []string
	}{
		{
			name:         "empty interface",
			iface:        model.Interface{},
			wantContains: nil,
		},
		{
			name: "basic interface fields",
			iface: model.Interface{
				If:      "em0",
				Enable:  "1",
				IPAddr:  "192.168.1.1",
				Subnet:  "24",
				Gateway: "192.168.1.254",
				MTU:     "1500",
			},
			wantContains: []string{
				"**Physical Interface**: em0",
				"**Enabled**: 1",
				"**IPv4 Address**: 192.168.1.1",
				"**IPv4 Subnet**: 24",
				"**Gateway**: 192.168.1.254",
				"**MTU**: 1500",
			},
		},
		{
			name: "ipv6 interface fields",
			iface: model.Interface{
				IPAddrv6: "2001:db8::1",
				Subnetv6: "64",
			},
			wantContains: []string{
				"**IPv6 Address**: 2001:db8::1",
				"**IPv6 Subnet**: 64",
			},
		},
		{
			name: "security fields",
			iface: model.Interface{
				BlockPriv:   "1",
				BlockBogons: "1",
			},
			wantContains: []string{
				"**Block Private Networks**: 1",
				"**Block Bogon Networks**: 1",
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
		rules        []model.Rule
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
			rules: []model.Rule{
				{
					Type:        "pass",
					Interface:   []string{"lan"},
					IPProtocol:  "inet",
					Protocol:    "tcp",
					Target:      "any",
					SourcePort:  "any",
					Descr:       "Allow LAN traffic",
					Source:      model.Source{Address: "192.168.1.0/24"},
					Destination: model.Destination{Address: "any", Port: "443"},
				},
			},
			wantRows: 1,
			wantContains: []string{
				"pass", "inet", "tcp", "192.168.1.0/24", "any", "443", "Allow LAN traffic",
			},
		},
		{
			name: "rule with disabled flag",
			rules: []model.Rule{
				{
					Type:      "block",
					Interface: []string{"wan"},
					Disabled:  model.BoolFlag(true),
					Descr:     "Disabled rule",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"block", "Disabled rule",
			},
		},
		{
			name: "rule with multiple interfaces",
			rules: []model.Rule{
				{
					Type:      "pass",
					Interface: []string{"lan", "wan", "opt1"},
					Protocol:  "udp",
					Descr:     "Multi-interface rule",
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
		rules        []model.NATRule
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
			rules: []model.NATRule{
				{
					Interface:   []string{"wan"},
					Protocol:    "tcp",
					Target:      "192.168.1.1",
					Descr:       "Web server NAT",
					Source:      model.Source{Address: "192.168.1.0/24"},
					Destination: model.Destination{Address: "any"},
				},
			},
			wantRows: 1,
			wantContains: []string{
				"⬆️ Outbound", "tcp", "192.168.1.0/24", "any", "`192.168.1.1`", "Web server NAT", "**Active**",
			},
		},
		{
			name: "disabled nat rule",
			rules: []model.NATRule{
				{
					Interface: []string{"wan"},
					Disabled:  model.BoolFlag(true),
					Descr:     "Disabled NAT",
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
		rules        []model.InboundRule
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
			rules: []model.InboundRule{
				{
					Interface:    []string{"wan"},
					Protocol:     "tcp",
					ExternalPort: "80",
					InternalIP:   "192.168.1.100",
					InternalPort: "80",
					Priority:     1,
					Descr:        "HTTP forward",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"⬇️ Inbound", "80", "`192.168.1.100`", "80", "tcp", "HTTP forward", "1", "**Active**",
			},
		},
		{
			name: "disabled inbound rule",
			rules: []model.InboundRule{
				{
					Interface: []string{"wan"},
					Disabled:  model.BoolFlag(true),
					Priority:  5,
					Descr:     "Disabled forward",
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
		interfaces   model.Interfaces
		wantRows     int
		wantContains []string
	}{
		{
			name: "empty interfaces",
			interfaces: model.Interfaces{
				Items: map[string]model.Interface{},
			},
			wantRows:     0,
			wantContains: nil,
		},
		{
			name: "single interface",
			interfaces: model.Interfaces{
				Items: map[string]model.Interface{
					"lan": {
						If:     "em0",
						Descr:  "LAN Interface",
						Enable: "1",
						IPAddr: "192.168.1.1",
						Subnet: "24",
					},
				},
			},
			wantRows: 1,
			wantContains: []string{
				"`lan`", "`LAN Interface`", "`192.168.1.1`", "/24", "✓",
			},
		},
		{
			name: "interface without description uses If field",
			interfaces: model.Interfaces{
				Items: map[string]model.Interface{
					"wan": {
						If:     "em1",
						Enable: "0",
						IPAddr: "dhcp",
					},
				},
			},
			wantRows: 1,
			wantContains: []string{
				"`wan`", "`em1`", "`dhcp`", "✗",
			},
		},
		{
			name: "multiple interfaces sorted by name",
			interfaces: model.Interfaces{
				Items: map[string]model.Interface{
					"wan":  {If: "em1", Enable: "1"},
					"lan":  {If: "em0", Enable: "1"},
					"opt1": {If: "em2", Enable: "0"},
				},
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
		users        []model.User
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
			users: []model.User{
				{
					Name:      "admin",
					Descr:     "System Administrator",
					Groupname: "admins",
					Scope:     "system",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"admin", "System Administrator", "admins", "system",
			},
		},
		{
			name: "multiple users",
			users: []model.User{
				{Name: "admin", Descr: "Administrator", Groupname: "admins", Scope: "system"},
				{Name: "user1", Descr: "Regular User", Groupname: "users", Scope: "user"},
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
		groups       []model.Group
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
			groups: []model.Group{
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
		sysctl       []model.SysctlItem
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
			sysctl: []model.SysctlItem{
				{
					Tunable: "kern.ipc.maxsockbuf",
					Value:   "16777216",
					Descr:   "Maximum socket buffer size",
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
		vlans        []model.VLAN
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
			vlans: []model.VLAN{
				{
					Vlanif:  "vlan10",
					If:      "em0",
					Tag:     "10",
					Descr:   "Management VLAN",
					Created: "2024-01-01",
					Updated: "2024-01-02",
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
		routes       []model.StaticRoute
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
			routes: []model.StaticRoute{
				{
					Network:  "10.0.0.0/8",
					Gateway:  "192.168.1.1",
					Descr:    "Internal networks",
					Disabled: false,
					Created:  "2024-01-01",
					Updated:  "2024-01-02",
				},
			},
			wantRows: 1,
			wantContains: []string{
				"10.0.0.0/8", "192.168.1.1", "Internal networks", "**Enabled**", "2024-01-01", "2024-01-02",
			},
		},
		{
			name: "disabled route",
			routes: []model.StaticRoute{
				{
					Network:  "172.16.0.0/12",
					Gateway:  "192.168.1.2",
					Descr:    "Disabled route",
					Disabled: true,
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
				rules := []model.Rule{
					{Type: "pass", Interface: []string{"lan"}, Descr: "Test rule"},
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
				interfaces := model.Interfaces{
					Items: map[string]model.Interface{
						"lan": {If: "em0", Enable: "1", IPAddr: "192.168.1.1"},
					},
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
				rules := []model.NATRule{
					{Interface: []string{"wan"}, Descr: "Test NAT"},
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
				rules := []model.InboundRule{
					{Interface: []string{"wan"}, Descr: "Test forward"},
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
				users := []model.User{
					{Name: "admin", Descr: "Administrator"},
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
				groups := []model.Group{
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
				sysctl := []model.SysctlItem{
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
				vlans := []model.VLAN{
					{Vlanif: "vlan10", Tag: "10"},
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
				routes := []model.StaticRoute{
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
				dhcpd := model.Dhcpd{
					Items: map[string]model.DhcpdInterface{
						"lan": {Enable: "1", Gateway: "192.168.1.1"},
					},
				}
				result := builder.WriteDHCPSummaryTable(md, dhcpd)
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
				leases := []model.DHCPStaticLease{
					{Mac: "00:11:22:33:44:55", IPAddr: "192.168.1.100"},
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

// Use helper functions from existing helpers_test.go
