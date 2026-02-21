package converter

import (
	"context"
	"strings"
	"testing"

	builderPkg "github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMarkdownBuilder(t *testing.T) {
	builder := NewMarkdownBuilder()
	assert.NotNil(t, builder)
	// Note: generated and toolVersion fields are now unexported for proper encapsulation
}

func TestMarkdownBuilder_BuildSystemSection(t *testing.T) {
	builder := NewMarkdownBuilder()

	// Create test data with NAT reflection disabled
	data := createComprehensiveTestData()
	data.System.DisableNATReflection = true // Override to disable NAT reflection

	result := builder.BuildSystemSection(data)

	// Verify the result contains expected sections
	assert.Contains(t, result, "System Configuration")
	assert.Contains(t, result, "Basic Information")
	assert.Contains(t, result, "Web GUI Configuration")
	assert.Contains(t, result, "System Settings")
	assert.Contains(t, result, "Hardware Offloading")
	assert.Contains(t, result, "Power Management")
	assert.Contains(t, result, "System Features")
	assert.Contains(t, result, "Bogons Configuration")
	assert.Contains(t, result, "SSH Configuration")
	assert.Contains(t, result, "Firmware Information")
	assert.Contains(t, result, "System Users")
	assert.Contains(t, result, "System Groups")

	// Verify specific values
	assert.Contains(t, result, "test-host")
	assert.Contains(t, result, "test.local")
	assert.Contains(t, result, "normal")
	assert.Contains(t, result, "UTC")
	assert.Contains(t, result, "en_US")
	assert.Contains(t, result, "https")
	assert.Contains(t, result, "wheel")
	assert.Contains(t, result, "23.1.1")
	assert.Contains(t, result, "daily")
	assert.Contains(t, result, "admin")
}

func TestMarkdownBuilder_BuildNetworkSection(t *testing.T) {
	builder := NewMarkdownBuilder()

	// Create test data with interfaces
	data := &common.CommonDevice{
		Interfaces: []common.Interface{
			{
				Name:         "wan",
				PhysicalIf:   "em0",
				Enabled:      true,
				IPAddress:    "192.168.1.1",
				Subnet:       "24",
				Gateway:      "192.168.1.254",
				MTU:          "1500",
				BlockPrivate: true,
				BlockBogons:  true,
				Description:  "WAN Interface",
			},
			{
				Name:         "lan",
				PhysicalIf:   "em1",
				Enabled:      true,
				IPAddress:    "10.0.0.1",
				Subnet:       "24",
				Gateway:      "",
				MTU:          "1500",
				BlockPrivate: false,
				BlockBogons:  false,
				Description:  "LAN Interface",
			},
		},
	}

	result := builder.BuildNetworkSection(data)

	// Verify the result contains expected sections
	assert.Contains(t, result, "Network Configuration")
	assert.Contains(t, result, "Interfaces")
	assert.Contains(t, result, "Wan Interface")
	assert.Contains(t, result, "Lan Interface")

	// Verify interface details
	assert.Contains(t, result, "em0")
	assert.Contains(t, result, "em1")
	assert.Contains(t, result, "192.168.1.1")
	assert.Contains(t, result, "10.0.0.1")
	assert.Contains(t, result, "WAN Interface")
	assert.Contains(t, result, "LAN Interface")
}

func TestMarkdownBuilder_BuildSecuritySection(t *testing.T) {
	builder := NewMarkdownBuilder()

	// Create test data with security configuration
	data := &common.CommonDevice{
		NAT: common.NATConfig{
			OutboundMode: "automatic",
		},
		FirewallRules: []common.FirewallRule{
			{
				Type:        "pass",
				Description: "Allow LAN to WAN",
				Interfaces:  []string{"lan"},
				IPProtocol:  "inet",
				Protocol:    "tcp",
				Source: common.RuleEndpoint{
					Address: "lan",
				},
				Destination: common.RuleEndpoint{
					Address: "any",
				},
				Target:   "",
				Disabled: false,
			},
			{
				Type:        "block",
				Description: "Block all",
				Interfaces:  []string{"wan"},
				IPProtocol:  "inet",
				Protocol:    "any",
				Source: common.RuleEndpoint{
					Address: "any",
				},
				Destination: common.RuleEndpoint{
					Address: "any",
				},
				Target:   "",
				Disabled: false,
			},
		},
	}

	result := builder.BuildSecuritySection(data)

	// Verify the result contains expected sections
	assert.Contains(t, result, "Security Configuration")
	assert.Contains(t, result, "NAT Configuration")
	assert.Contains(t, result, "Firewall Rules")

	// Verify NAT configuration
	assert.Contains(t, result, "automatic")

	// Verify firewall rules
	assert.Contains(t, result, "Allow LAN to WAN")
	assert.Contains(t, result, "Block all")
	assert.Contains(t, result, "pass")
	assert.Contains(t, result, "block")
	assert.Contains(t, result, "lan")
	assert.Contains(t, result, "wan")
}

func TestMarkdownBuilder_BuildServicesSection(t *testing.T) {
	builder := NewMarkdownBuilder()

	// Create test data with services configuration
	data := &common.CommonDevice{
		DHCP: []common.DHCPScope{
			{
				Interface: "lan",
				Enabled:   true,
				Range: common.DHCPRange{
					From: "10.0.0.100",
					To:   "10.0.0.200",
				},
			},
			{
				Interface: "wan",
				Enabled:   true,
			},
		},
		DNS: common.DNSConfig{
			Unbound: common.UnboundConfig{
				Enabled: true,
			},
		},
		SNMP: common.SNMPConfig{
			SysLocation: "Data Center",
			SysContact:  "admin@example.com",
			ROCommunity: "public",
		},
		NTP: common.NTPConfig{
			PreferredServer: "pool.ntp.org",
		},
		LoadBalancer: common.LoadBalancerConfig{
			MonitorTypes: []common.MonitorType{
				{
					Name:        "http-monitor",
					Type:        "http",
					Description: "HTTP Health Check",
				},
			},
		},
	}

	result := builder.BuildServicesSection(data)

	// Verify the result contains expected sections
	assert.Contains(t, result, "Service Configuration")
	assert.Contains(t, result, "DHCP Server")
	assert.Contains(t, result, "DNS Resolver (Unbound)")
	assert.Contains(t, result, "SNMP")
	assert.Contains(t, result, "NTP")
	assert.Contains(t, result, "Load Balancer Monitors")

	// Verify service details
	assert.Contains(t, result, "10.0.0.100")
	assert.Contains(t, result, "10.0.0.200")
	assert.Contains(t, result, "Data Center")
	assert.Contains(t, result, "admin@example.com")
	assert.Contains(t, result, "public")
	assert.Contains(t, result, "pool.ntp.org")
	assert.Contains(t, result, "http-monitor")
	assert.Contains(t, result, "HTTP Health Check")
}

func TestMarkdownBuilder_BuildFirewallRulesTable(t *testing.T) {
	rules := []common.FirewallRule{
		{
			Type:        "pass",
			Description: "Allow LAN to WAN",
			Interfaces:  []string{"lan"},
			IPProtocol:  "inet",
			Protocol:    "tcp",
			Source: common.RuleEndpoint{
				Address: "lan",
				Port:    "80",
			},
			Destination: common.RuleEndpoint{
				Address: "any",
			},
			Target:   "",
			Disabled: false,
		},
	}

	tableSet := builderPkg.BuildFirewallRulesTableSet(rules)

	assert.NotNil(t, tableSet)
	assert.Len(t, tableSet.Header, 12)
	assert.Len(t, tableSet.Rows, 1)

	// Verify headers
	expectedHeaders := []string{
		"#",
		"Interface",
		"Action",
		"IP Ver",
		"Proto",
		"Source",
		"Destination",
		"Target",
		"Source Port",
		"Dest Port",
		"Enabled",
		"Description",
	}
	assert.Equal(t, expectedHeaders, tableSet.Header)

	// Verify first row
	row := tableSet.Rows[0]
	assert.Equal(t, "1", row[0])                 // #
	assert.Contains(t, row[1], "lan")            // Interface (with link)
	assert.Equal(t, "pass", row[2])              // Action
	assert.Equal(t, "inet", row[3])              // IP Ver
	assert.Equal(t, "tcp", row[4])               // Proto
	assert.Equal(t, "lan", row[5])               // Source
	assert.Equal(t, "any", row[6])               // Destination
	assert.Empty(t, row[7])                      // Target
	assert.Equal(t, "80", row[8])                // Source Port
	assert.Empty(t, row[9])                      // Dest Port
	assert.Equal(t, "✓", row[10])                // Enabled
	assert.Equal(t, "Allow LAN to WAN", row[11]) // Description
}

func TestMarkdownBuilder_BuildInterfaceTable(t *testing.T) {
	interfaces := []common.Interface{
		{
			Name:        "wan",
			PhysicalIf:  "em0",
			Enabled:     true,
			IPAddress:   "192.168.1.1",
			Subnet:      "24",
			Description: "WAN Interface",
		},
		{
			Name:        "lan",
			PhysicalIf:  "em1",
			Enabled:     true,
			IPAddress:   "10.0.0.1",
			Subnet:      "24",
			Description: "LAN Interface",
		},
	}

	tableSet := builderPkg.BuildInterfaceTableSet(interfaces)

	assert.NotNil(t, tableSet)
	assert.Len(t, tableSet.Header, 5)
	assert.Len(t, tableSet.Rows, 2)

	// Verify headers
	expectedHeaders := []string{"Name", "Description", "IP Address", "CIDR", "Enabled"}
	assert.Equal(t, expectedHeaders, tableSet.Header)

	// Verify rows contain expected data
	rowData := make(map[string][]string)
	for _, row := range tableSet.Rows {
		rowData[row[0]] = row
	}

	// Check WAN interface
	wanRow := rowData["`wan`"]
	assert.NotNil(t, wanRow)
	assert.Equal(t, "`WAN Interface`", wanRow[1])
	assert.Equal(t, "`192.168.1.1`", wanRow[2])
	assert.Equal(t, "/24", wanRow[3])
	assert.Equal(t, "✓", wanRow[4])

	// Check LAN interface
	lanRow := rowData["`lan`"]
	assert.NotNil(t, lanRow)
	assert.Equal(t, "`LAN Interface`", lanRow[1])
	assert.Equal(t, "`10.0.0.1`", lanRow[2])
	assert.Equal(t, "/24", lanRow[3])
	assert.Equal(t, "✓", lanRow[4])
}

func TestMarkdownBuilder_BuildUserTable(t *testing.T) {
	users := []common.User{
		{
			Name:        "admin",
			Description: "Administrator",
			GroupName:   "wheel",
			Scope:       "system",
		},
		{
			Name:        "user1",
			Description: "Regular User",
			GroupName:   "users",
			Scope:       "local",
		},
	}

	tableSet := builderPkg.BuildUserTableSet(users)

	assert.NotNil(t, tableSet)
	assert.Len(t, tableSet.Header, 4)
	assert.Len(t, tableSet.Rows, 2)

	// Verify headers
	expectedHeaders := []string{"Name", "Description", "Group", "Scope"}
	assert.Equal(t, expectedHeaders, tableSet.Header)

	// Verify first row
	row := tableSet.Rows[0]
	assert.Equal(t, "admin", row[0])
	assert.Equal(t, "Administrator", row[1])
	assert.Equal(t, "wheel", row[2])
	assert.Equal(t, "system", row[3])
}

func TestMarkdownBuilder_BuildGroupTable(t *testing.T) {
	groups := []common.Group{
		{
			Name:        "wheel",
			Description: "Wheel group",
			Scope:       "system",
		},
		{
			Name:        "users",
			Description: "Regular users",
			Scope:       "local",
		},
	}

	tableSet := builderPkg.BuildGroupTableSet(groups)

	assert.NotNil(t, tableSet)
	assert.Len(t, tableSet.Header, 3)
	assert.Len(t, tableSet.Rows, 2)

	// Verify headers
	expectedHeaders := []string{"Name", "Description", "Scope"}
	assert.Equal(t, expectedHeaders, tableSet.Header)

	// Verify first row
	row := tableSet.Rows[0]
	assert.Equal(t, "wheel", row[0])
	assert.Equal(t, "Wheel group", row[1])
	assert.Equal(t, "system", row[2])
}

func TestMarkdownBuilder_BuildSysctlTable(t *testing.T) {
	sysctl := []common.SysctlItem{
		{
			Tunable:     "net.inet.ip.forwarding",
			Value:       "1",
			Description: "Enable IP forwarding",
		},
		{
			Tunable:     "net.inet.tcp.always_keepalive",
			Value:       "0",
			Description: "Disable TCP keepalive",
		},
	}

	tableSet := builderPkg.BuildSysctlTableSet(sysctl)

	assert.NotNil(t, tableSet)
	assert.Len(t, tableSet.Header, 3)
	assert.Len(t, tableSet.Rows, 2)

	// Verify headers
	expectedHeaders := []string{"Tunable", "Value", "Description"}
	assert.Equal(t, expectedHeaders, tableSet.Header)

	// Verify first row
	row := tableSet.Rows[0]
	assert.Equal(t, "net.inet.ip.forwarding", row[0])
	assert.Equal(t, "1", row[1])
	assert.Equal(t, "Enable IP forwarding", row[2])
}

func TestMarkdownBuilder_BuildStandardReport(t *testing.T) {
	builder := NewMarkdownBuilder()

	data := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
			Firmware: common.Firmware{
				Version: "23.1.1",
			},
		},
		Interfaces: []common.Interface{
			{
				Name:       "wan",
				PhysicalIf: "em0",
				Enabled:    true,
				IPAddress:  "192.168.1.1",
				Subnet:     "24",
			},
		},
	}

	result, err := builder.BuildStandardReport(data)

	require.NoError(t, err)
	assert.NotEmpty(t, result)

	// Verify report structure
	assert.Contains(t, result, "OPNsense Configuration Summary")
	assert.Contains(t, result, "System Information")
	assert.Contains(t, result, "Table of Contents")
	assert.Contains(t, result, "Interfaces")
	assert.Contains(t, result, "Firewall Rules")
	assert.Contains(t, result, "NAT Configuration")
	assert.Contains(t, result, "DHCP Services")
	assert.Contains(t, result, "DNS Resolver")
	assert.Contains(t, result, "System Users")
	assert.Contains(t, result, "Services & Daemons")
	assert.Contains(t, result, "System Tunables")

	// Verify data
	assert.Contains(t, result, "test-host")
	assert.Contains(t, result, "test.local")
	assert.Contains(t, result, "23.1.1")
	assert.Contains(t, result, "192.168.1.1")
}

func TestMarkdownBuilder_BuildComprehensiveReport(t *testing.T) {
	builder := NewMarkdownBuilder()

	data := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
			Firmware: common.Firmware{
				Version: "23.1.1",
			},
		},
		Interfaces: []common.Interface{
			{
				Name:       "wan",
				PhysicalIf: "em0",
				Enabled:    true,
				IPAddress:  "192.168.1.1",
				Subnet:     "24",
			},
		},
	}

	result, err := builder.BuildComprehensiveReport(data)

	require.NoError(t, err)
	assert.NotEmpty(t, result)

	// Verify report structure
	assert.Contains(t, result, "OPNsense Configuration Summary")
	assert.Contains(t, result, "System Information")
	assert.Contains(t, result, "Table of Contents")
	assert.Contains(t, result, "System Configuration")
	assert.Contains(t, result, "Interfaces")
	assert.Contains(t, result, "Firewall Rules")
	assert.Contains(t, result, "NAT Configuration")
	assert.Contains(t, result, "DHCP Services")
	assert.Contains(t, result, "DNS Resolver")
	assert.Contains(t, result, "System Users")
	assert.Contains(t, result, "System Groups")
	assert.Contains(t, result, "Services & Daemons")
	assert.Contains(t, result, "System Tunables")

	// Verify data
	assert.Contains(t, result, "test-host")
	assert.Contains(t, result, "test.local")
	assert.Contains(t, result, "23.1.1")
	assert.Contains(t, result, "192.168.1.1")
}

func TestMarkdownBuilder_BuildStandardReport_NilData(t *testing.T) {
	builder := NewMarkdownBuilder()

	result, err := builder.BuildStandardReport(nil)

	require.Error(t, err)
	assert.Empty(t, result)
	assert.Equal(t, builderPkg.ErrNilDevice, err)
}

func TestMarkdownBuilder_BuildComprehensiveReport_NilData(t *testing.T) {
	builder := NewMarkdownBuilder()

	result, err := builder.BuildComprehensiveReport(nil)

	require.Error(t, err)
	assert.Empty(t, result)
	assert.Equal(t, builderPkg.ErrNilDevice, err)
}

func TestFormatBoolean(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"true value", "1", "✓"},
		{"true string", "true", "✓"},
		{"on value", "on", "✓"},
		{"false value", "0", "✗"},
		{"false string", "false", "✗"},
		{"empty string", "", "✗"},
		{"random string", "random", "✗"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatters.FormatBoolean(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatIntBoolean(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{"true value", 1, "✓"},
		{"false value", 0, "✗"},
		{"negative value", -1, "✗"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatters.FormatIntBoolean(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatBool(t *testing.T) {
	tests := []struct {
		name     string
		input    bool
		expected string
	}{
		{"true value", true, "✓"},
		{"false value", false, "✗"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatters.FormatBool(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetPowerModeDescription(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"hadp", "hadp", "Adaptive (hadp)"},
		{"maximum", "maximum", "Maximum Performance (maximum)"},
		{"minimum", "minimum", "Minimum Power (minimum)"},
		{"hiadaptive", "hiadaptive", "High Adaptive (hiadaptive)"},
		{"adaptive", "adaptive", "Adaptive (adaptive)"},
		{"unknown", "unknown", "unknown"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatters.GetPowerModeDescriptionCompact(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildFirewallRulesTable_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		rules []common.FirewallRule
	}{
		{
			name:  "empty_rules",
			rules: []common.FirewallRule{},
		},
		{
			name: "rules_with_empty_networks",
			rules: []common.FirewallRule{
				{
					Type:        "pass",
					Interfaces:  []string{"lan"},
					IPProtocol:  "inet",
					Protocol:    "tcp",
					Source:      common.RuleEndpoint{Address: ""},
					Destination: common.RuleEndpoint{Address: ""},
					Description: "Test rule",
				},
			},
		},
		{
			name: "rules_with_nil_interface",
			rules: []common.FirewallRule{
				{
					Type:        "pass",
					Interfaces:  nil,
					IPProtocol:  "inet",
					Protocol:    "tcp",
					Source:      common.RuleEndpoint{Address: "lan"},
					Destination: common.RuleEndpoint{Address: "any"},
					Description: "Test rule",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builderPkg.BuildFirewallRulesTableSet(tt.rules)
			assert.NotNil(t, result)
			assert.Len(t, result.Header, 12) // Should have 12 headers
		})
	}
}

func TestBuildFirewallRulesTable_AnyFieldAndDestPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		rule       common.FirewallRule
		wantSource string
		wantDest   string
		wantDPort  string
	}{
		{
			name: "source_any_via_address",
			rule: common.FirewallRule{
				Type:        "pass",
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "lan"},
			},
			wantSource: "any",
			wantDest:   "lan",
			wantDPort:  "",
		},
		{
			name: "source_any_empty_address",
			rule: common.FirewallRule{
				Type:        "pass",
				Source:      common.RuleEndpoint{Address: ""},
				Destination: common.RuleEndpoint{Address: "wan"},
			},
			wantSource: "any",
			wantDest:   "wan",
			wantDPort:  "",
		},
		{
			name: "destination_any_via_address",
			rule: common.FirewallRule{
				Type:        "pass",
				Source:      common.RuleEndpoint{Address: "lan"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
			wantSource: "lan",
			wantDest:   "any",
			wantDPort:  "",
		},
		{
			name: "destination_any_empty_address",
			rule: common.FirewallRule{
				Type:        "pass",
				Source:      common.RuleEndpoint{Address: "lan"},
				Destination: common.RuleEndpoint{Address: ""},
			},
			wantSource: "lan",
			wantDest:   "any",
			wantDPort:  "",
		},
		{
			name: "both_absent_shows_any",
			rule: common.FirewallRule{
				Type:        "pass",
				Source:      common.RuleEndpoint{},
				Destination: common.RuleEndpoint{},
			},
			wantSource: "any",
			wantDest:   "any",
			wantDPort:  "",
		},
		{
			name: "destination_port_populated",
			rule: common.FirewallRule{
				Type:        "pass",
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "wan", Port: "443"},
			},
			wantSource: "any",
			wantDest:   "wan",
			wantDPort:  "443",
		},
		{
			name: "destination_any_with_port",
			rule: common.FirewallRule{
				Type:        "pass",
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "any", Port: "80,443"},
			},
			wantSource: "any",
			wantDest:   "any",
			wantDPort:  "80,443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := builderPkg.BuildFirewallRulesTableSet([]common.FirewallRule{tt.rule})
			assert.Len(t, result.Header, 12)
			assert.Len(t, result.Rows, 1)
			row := result.Rows[0]
			assert.Equal(t, tt.wantSource, row[5], "Source column")
			assert.Equal(t, tt.wantDest, row[6], "Destination column")
			assert.Equal(t, tt.wantDPort, row[9], "Dest Port column")
		})
	}
}

func TestBuildStandardReport_EdgeCases(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name string
		data *common.CommonDevice
	}{
		{
			name: "empty_system_config",
			data: &common.CommonDevice{
				System: common.System{},
			},
		},
		{
			name: "minimal_data",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "test.local",
				},
			},
		},
		{
			name: "data_with_empty_interfaces",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				Interfaces: []common.Interface{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := builder.BuildStandardReport(tt.data)
			require.NoError(t, err)
			assert.NotEmpty(t, result)
			assert.Contains(t, result, "OPNsense Configuration Summary")
		})
	}
}

func TestBuildSecuritySection_EdgeCases(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name string
		data *common.CommonDevice
	}{
		{
			name: "no_nat_config",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "test.local",
				},
			},
		},
		{
			name: "no_firewall_rules",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				FirewallRules: []common.FirewallRule{},
			},
		},
		{
			name: "nat_without_outbound",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				NAT: common.NATConfig{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.BuildSecuritySection(tt.data)
			assert.NotEmpty(t, result)
			assert.Contains(t, result, "Security Configuration")
		})
	}
}

func TestBuildServicesSection_EdgeCases(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name string
		data *common.CommonDevice
	}{
		{
			name: "no_dhcp_config",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "test.local",
				},
			},
		},
		{
			name: "no_unbound_config",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				DNS: common.DNSConfig{},
			},
		},
		{
			name: "no_snmp_config",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				SNMP: common.SNMPConfig{},
			},
		},
		{
			name: "no_ntpd_config",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				NTP: common.NTPConfig{},
			},
		},
		{
			name: "no_load_balancer_config",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				LoadBalancer: common.LoadBalancerConfig{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.BuildServicesSection(tt.data)
			assert.NotEmpty(t, result)
			assert.Contains(t, result, "Service Configuration")
		})
	}
}

func TestToMarkdown_EdgeCases(t *testing.T) {
	converter := NewMarkdownConverter()

	tests := []struct {
		name string
		data *common.CommonDevice
	}{
		{
			name: "empty_opnsense",
			data: &common.CommonDevice{},
		},
		{
			name: "minimal_opnsense",
			data: &common.CommonDevice{
				System: common.System{
					Hostname: "test",
					Domain:   "test.local",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := converter.ToMarkdown(context.Background(), tt.data)
			require.NoError(t, err)
			assert.NotEmpty(t, result)
			// Remove ANSI color codes for comparison
			cleanResult := strings.ReplaceAll(result, "\x1b[38;5;228;48;5;63;1m", "")
			cleanResult = strings.ReplaceAll(cleanResult, "\x1b[0m", "")
			cleanResult = strings.ReplaceAll(cleanResult, "\x1b[38;5;252m", "")
			cleanResult = strings.ReplaceAll(cleanResult, "\x1b[38;5;39;1m", "")
			cleanResult = strings.ReplaceAll(cleanResult, "\x1b[38;5;252;1m", "")
			assert.Contains(t, cleanResult, "OPNsense Configuration")
		})
	}
}

func TestGetTheme_EdgeCases(t *testing.T) {
	converter := NewMarkdownConverter()

	// Test with different environment variables
	tests := []struct {
		name          string
		envVars       map[string]string
		expectedTheme string
	}{
		{
			name: "default_theme",
			envVars: map[string]string{
				"TERM":      "dumb",
				"COLORTERM": "",
			},
			expectedTheme: "auto",
		},
		{
			name: "explicit_theme",
			envVars: map[string]string{
				"OPNDOSSIER_THEME": "dark",
			},
			expectedTheme: "dark",
		},
		{
			name: "colorterm_truecolor",
			envVars: map[string]string{
				"COLORTERM": "truecolor",
				"TERM":      "xterm-256color",
			},
			expectedTheme: "dark",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables for test
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			theme := converter.getTheme()
			assert.Equal(t, tt.expectedTheme, theme)
		})
	}
}

// Test that the MarkdownBuilder implements the ReportBuilder interface.
func TestMarkdownBuilder_ImplementsReportBuilder(_ *testing.T) {
	var _ ReportBuilder = (*MarkdownBuilder)(nil)
}

// Integration test comparing with the old MarkdownConverter.
func TestMarkdownBuilder_IntegrationWithOldConverter(t *testing.T) {
	// Create test data
	data := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
			Firmware: common.Firmware{
				Version: "23.1.1",
			},
		},
		Interfaces: []common.Interface{
			{
				Name:       "wan",
				PhysicalIf: "em0",
				Enabled:    true,
				IPAddress:  "192.168.1.1",
				Subnet:     "24",
			},
		},
	}

	// Test new builder
	builder := NewMarkdownBuilder()
	newResult, err := builder.BuildStandardReport(data)
	require.NoError(t, err)

	// Test old converter
	converter := NewMarkdownConverter()
	oldResult, err := converter.ToMarkdown(context.Background(), data)
	require.NoError(t, err)

	// Both should produce valid markdown
	assert.NotEmpty(t, newResult)
	assert.NotEmpty(t, oldResult)

	// Both should contain the same basic information
	assert.Contains(t, newResult, "test-host")
	assert.Contains(t, newResult, "test.local")
	assert.Contains(t, newResult, "23.1.1")

	// The new builder should have more comprehensive output
	assert.Contains(t, newResult, "System Configuration")
	assert.Contains(t, newResult, "Network Configuration")
	assert.Contains(t, newResult, "Security Configuration")
	assert.Contains(t, newResult, "Service Configuration")
}

// Benchmark tests for performance comparison.
func BenchmarkMarkdownBuilder_BuildStandardReport(b *testing.B) {
	builder := NewMarkdownBuilder()

	data := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
			Firmware: common.Firmware{
				Version: "23.1.1",
			},
		},
		Interfaces: []common.Interface{
			{
				Name:       "wan",
				PhysicalIf: "em0",
				Enabled:    true,
				IPAddress:  "192.168.1.1",
				Subnet:     "24",
			},
			{
				Name:       "lan",
				PhysicalIf: "em1",
				Enabled:    true,
				IPAddress:  "10.0.0.1",
				Subnet:     "24",
			},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := builder.BuildStandardReport(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarkdownBuilder_BuildComprehensiveReport(b *testing.B) {
	builder := NewMarkdownBuilder()

	data := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
			Firmware: common.Firmware{
				Version: "23.1.1",
			},
		},
		Interfaces: []common.Interface{
			{
				Name:       "wan",
				PhysicalIf: "em0",
				Enabled:    true,
				IPAddress:  "192.168.1.1",
				Subnet:     "24",
			},
			{
				Name:       "lan",
				PhysicalIf: "em1",
				Enabled:    true,
				IPAddress:  "10.0.0.1",
				Subnet:     "24",
			},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := builder.BuildComprehensiveReport(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Test additional edge cases and missing coverage scenarios.
func TestMarkdownBuilder_BuildSecuritySection_WithNATReflection(t *testing.T) {
	builder := NewMarkdownBuilder()

	// Test with NAT reflection enabled
	data := &common.CommonDevice{
		System: common.System{
			DisableNATReflection: false, // NAT reflection enabled
			PfShareForward:       true,
		},
		NAT: common.NATConfig{
			OutboundMode: "automatic",
		},
		FirewallRules: []common.FirewallRule{
			{
				Type:        "pass",
				Description: "Test rule",
				Interfaces:  []string{"lan"},
				IPProtocol:  "inet",
				Protocol:    "tcp",
				Source: common.RuleEndpoint{
					Address: "lan",
				},
				Destination: common.RuleEndpoint{
					Address: "any",
				},
			},
		},
	}

	result := builder.BuildSecuritySection(data)

	// Verify NAT reflection warning is present when enabled (GitHub-flavored alert)
	assert.Contains(t, result, "[!WARNING]")
	assert.Contains(t, result, "NAT reflection is enabled")
}

func TestMarkdownBuilder_BuildServicesSection_WithLoadBalancerMonitors(t *testing.T) {
	builder := NewMarkdownBuilder()

	// Test with load balancer monitors
	data := &common.CommonDevice{
		LoadBalancer: common.LoadBalancerConfig{
			MonitorTypes: []common.MonitorType{
				{
					Name:        "http-monitor",
					Type:        "http",
					Description: "HTTP Health Check",
				},
				{
					Name:        "tcp-monitor",
					Type:        "tcp",
					Description: "TCP Health Check",
				},
			},
		},
	}

	result := builder.BuildServicesSection(data)

	// Verify load balancer monitors are included
	assert.Contains(t, result, "Load Balancer Monitors")
	assert.Contains(t, result, "http-monitor")
	assert.Contains(t, result, "tcp-monitor")
	assert.Contains(t, result, "HTTP Health Check")
	assert.Contains(t, result, "TCP Health Check")
}

func TestMarkdownBuilder_BuildStandardReport_WithUsersAndSysctl(t *testing.T) {
	builder := NewMarkdownBuilder()

	// Test with users and sysctl data
	data := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
		Users: []common.User{
			{
				Name:        "admin",
				Description: "Administrator",
				GroupName:   "wheel",
				Scope:       "system",
			},
			{
				Name:        "user1",
				Description: "Regular User",
				GroupName:   "users",
				Scope:       "local",
			},
		},
		Sysctl: []common.SysctlItem{
			{
				Tunable:     "net.inet.ip.forwarding",
				Value:       "1",
				Description: "Enable IP forwarding",
			},
			{
				Tunable:     "net.inet.tcp.always_keepalive",
				Value:       "0",
				Description: "Disable TCP keepalive",
			},
		},
	}

	result, err := builder.BuildStandardReport(data)

	require.NoError(t, err)
	assert.NotEmpty(t, result)

	// Verify users and sysctl sections are included
	assert.Contains(t, result, "System Users")
	assert.Contains(t, result, "System Tunables")
	assert.Contains(t, result, "admin")
	assert.Contains(t, result, "user1")
	assert.Contains(t, result, "net.inet.ip.forwarding")
	assert.Contains(t, result, "net.inet.tcp.always\\_keepalive")
}

func TestMarkdownBuilder_BuildComprehensiveReport_WithGroups(t *testing.T) {
	builder := NewMarkdownBuilder()

	// Test comprehensive report with groups
	data := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
		Groups: []common.Group{
			{
				Name:        "wheel",
				Description: "Wheel group",
				Scope:       "system",
			},
			{
				Name:        "users",
				Description: "Regular users",
				Scope:       "local",
			},
		},
	}

	result, err := builder.BuildComprehensiveReport(data)

	require.NoError(t, err)
	assert.NotEmpty(t, result)

	// Verify groups section is included in comprehensive report
	assert.Contains(t, result, "System Groups")
	assert.Contains(t, result, "wheel")
	assert.Contains(t, result, "users")
}

func TestMarkdownBuilder_BuildFirewallRulesTable_WithComplexRules(t *testing.T) {
	// Test with complex firewall rules including all fields
	rules := []common.FirewallRule{
		{
			Type:        "pass",
			Description: "Allow HTTPS",
			Interfaces:  []string{"wan"},
			IPProtocol:  "inet",
			Protocol:    "tcp",
			Source: common.RuleEndpoint{
				Address: "any",
				Port:    "443",
			},
			Destination: common.RuleEndpoint{
				Address: "lan",
			},
			Target:   "lan",
			Disabled: true, // Disabled rule
		},
		{
			Type:        "block",
			Description: "Block SSH",
			Interfaces:  []string{"wan", "lan"},
			IPProtocol:  "inet6",
			Protocol:    "tcp",
			Source: common.RuleEndpoint{
				Address: "lan",
				Port:    "22",
			},
			Destination: common.RuleEndpoint{
				Address: "wan",
			},
			Target:   "",
			Disabled: false,
		},
	}

	tableSet := builderPkg.BuildFirewallRulesTableSet(rules)

	assert.NotNil(t, tableSet)
	assert.Len(t, tableSet.Header, 12)
	assert.Len(t, tableSet.Rows, 2)

	// Verify first row (disabled rule)
	row1 := tableSet.Rows[0]
	assert.Equal(t, "1", row1[0])            // #
	assert.Contains(t, row1[1], "wan")       // Interface
	assert.Equal(t, "pass", row1[2])         // Action
	assert.Equal(t, "inet", row1[3])         // IP Ver
	assert.Equal(t, "tcp", row1[4])          // Proto
	assert.Equal(t, "any", row1[5])          // Source
	assert.Equal(t, "lan", row1[6])          // Destination
	assert.Equal(t, "lan", row1[7])          // Target
	assert.Equal(t, "443", row1[8])          // Source Port
	assert.Empty(t, row1[9])                 // Dest Port
	assert.Equal(t, "✗", row1[10])           // Enabled (disabled)
	assert.Equal(t, "Allow HTTPS", row1[11]) // Description

	// Verify second row (enabled rule)
	row2 := tableSet.Rows[1]
	assert.Equal(t, "2", row2[0])          // #
	assert.Contains(t, row2[1], "wan")     // Interface
	assert.Contains(t, row2[1], "lan")     // Interface
	assert.Equal(t, "block", row2[2])      // Action
	assert.Equal(t, "inet6", row2[3])      // IP Ver
	assert.Equal(t, "tcp", row2[4])        // Proto
	assert.Equal(t, "lan", row2[5])        // Source
	assert.Equal(t, "wan", row2[6])        // Destination
	assert.Empty(t, row2[7])               // Target
	assert.Equal(t, "22", row2[8])         // Source Port
	assert.Empty(t, row2[9])               // Dest Port
	assert.Equal(t, "✓", row2[10])         // Enabled
	assert.Equal(t, "Block SSH", row2[11]) // Description
}

func TestMarkdownBuilder_BuildInterfaceTable_WithComplexInterfaces(t *testing.T) {
	// Test with complex interface configurations
	interfaces := []common.Interface{
		{
			Name:         "wan",
			PhysicalIf:   "em0",
			Enabled:      true,
			IPAddress:    "192.168.1.1",
			Subnet:       "24",
			Gateway:      "192.168.1.254",
			MTU:          "1500",
			BlockPrivate: true,
			BlockBogons:  true,
			Description:  "WAN Interface",
		},
		{
			Name:         "lan",
			PhysicalIf:   "em1",
			Enabled:      false, // Disabled interface
			IPAddress:    "10.0.0.1",
			Subnet:       "24",
			Gateway:      "",
			MTU:          "1500",
			BlockPrivate: false,
			BlockBogons:  false,
			Description:  "LAN Interface",
		},
		{
			Name:         "opt1",
			PhysicalIf:   "em2",
			Enabled:      true,
			IPAddress:    "172.16.0.1",
			Subnet:       "16",
			Gateway:      "",
			MTU:          "9000",
			BlockPrivate: false,
			BlockBogons:  false,
			Description:  "DMZ Interface",
		},
	}

	tableSet := builderPkg.BuildInterfaceTableSet(interfaces)

	assert.NotNil(t, tableSet)
	assert.Len(t, tableSet.Header, 5)
	assert.Len(t, tableSet.Rows, 3)

	// Verify all interfaces are present
	interfaceNames := make(map[string]bool)
	for _, row := range tableSet.Rows {
		interfaceNames[row[0]] = true
	}

	assert.True(t, interfaceNames["`wan`"])
	assert.True(t, interfaceNames["`lan`"])
	assert.True(t, interfaceNames["`opt1`"])

	// Verify specific interface details
	rowData := make(map[string][]string)
	for _, row := range tableSet.Rows {
		rowData[row[0]] = row
	}

	// Check WAN interface (enabled)
	wanRow := rowData["`wan`"]
	assert.Equal(t, "`WAN Interface`", wanRow[1])
	assert.Equal(t, "`192.168.1.1`", wanRow[2])
	assert.Equal(t, "/24", wanRow[3])
	assert.Equal(t, "✓", wanRow[4])

	// Check LAN interface (disabled)
	lanRow := rowData["`lan`"]
	assert.Equal(t, "`LAN Interface`", lanRow[1])
	assert.Equal(t, "`10.0.0.1`", lanRow[2])
	assert.Equal(t, "/24", lanRow[3])
	assert.Equal(t, "✗", lanRow[4])

	// Check OPT1 interface (enabled)
	opt1Row := rowData["`opt1`"]
	assert.Equal(t, "`DMZ Interface`", opt1Row[1])
	assert.Equal(t, "`172.16.0.1`", opt1Row[2])
	assert.Equal(t, "/16", opt1Row[3])
	assert.Equal(t, "✓", opt1Row[4])
}

func TestFormatIntBooleanWithUnset(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{"true value", 1, "✓"},
		{"false value", 0, "unset"},
		{"unset value", -1, "✗"},
		{"negative value", -5, "✗"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatters.FormatIntBooleanWithUnset(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMarkdownBuilder_BuildSystemSection_WithAllFields(t *testing.T) {
	builder := NewMarkdownBuilder()

	// Test with comprehensive system configuration
	data := createComprehensiveTestData()

	result := builder.BuildSystemSection(data)

	// Verify all sections are present
	assert.Contains(t, result, "System Configuration")
	assert.Contains(t, result, "Basic Information")
	assert.Contains(t, result, "Web GUI Configuration")
	assert.Contains(t, result, "System Settings")
	assert.Contains(t, result, "Hardware Offloading")
	assert.Contains(t, result, "Power Management")
	assert.Contains(t, result, "System Features")
	assert.Contains(t, result, "Bogons Configuration")
	assert.Contains(t, result, "SSH Configuration")
	assert.Contains(t, result, "Firmware Information")
	assert.Contains(t, result, "System Users")
	assert.Contains(t, result, "System Groups")

	// Verify specific values
	assert.Contains(t, result, "test-host")
	assert.Contains(t, result, "test.local")
	assert.Contains(t, result, "normal")
	assert.Contains(t, result, "UTC")
	assert.Contains(t, result, "en_US")
	assert.Contains(t, result, "https")
	assert.Contains(t, result, "wheel")
	assert.Contains(t, result, "23.1.1")
	assert.Contains(t, result, "daily")
	assert.Contains(t, result, "admin")
	assert.Contains(t, result, "8.8.8.8")
	assert.Contains(t, result, "pool.ntp.org")
}

// createComprehensiveTestData creates a comprehensive test data structure.
func createComprehensiveTestData() *common.CommonDevice {
	return &common.CommonDevice{
		System: common.System{
			Hostname:                      "test-host",
			Domain:                        "test.local",
			Optimization:                  "normal",
			Timezone:                      "UTC",
			Language:                      "en_US",
			DNSAllowOverride:              true,
			NextUID:                       1000,
			NextGID:                       1000,
			TimeServers:                   []string{"pool.ntp.org"},
			DNSServers:                    []string{"8.8.8.8"},
			UseVirtualTerminal:            true,
			DisableVLANHWFilter:           false,
			DisableChecksumOffloading:     false,
			DisableSegmentationOffloading: false,
			DisableLargeReceiveOffloading: false,
			IPv6Allow:                     true,
			DisableNATReflection:          false, // NAT reflection enabled
			PowerdACMode:                  "adaptive",
			PowerdBatteryMode:             "minimum",
			PowerdNormalMode:              "adaptive",
			PfShareForward:                true,
			LbUseSticky:                   false,
			RrdBackup:                     true,
			NetflowBackup:                 false,
			WebGUI: common.WebGUI{
				Protocol: "https",
			},
			SSH: common.SSH{
				Group: "wheel",
			},
			Firmware: common.Firmware{
				Version: "23.1.1",
			},
			Bogons: common.Bogons{
				Interval: "daily",
			},
		},
		Users: []common.User{
			{
				Name:        "admin",
				Description: "Administrator",
				GroupName:   "wheel",
				Scope:       "system",
			},
		},
		Groups: []common.Group{
			{
				Name:        "wheel",
				Description: "Wheel group",
				Scope:       "system",
			},
		},
		Sysctl: []common.SysctlItem{
			{
				Tunable:     "net.inet.ip.forwarding",
				Value:       "1",
				Description: "Enable IP forwarding",
			},
		},
	}
}

func TestMarkdownBuilder_BuildNetworkSection_WithComplexInterfaces(t *testing.T) {
	builder := NewMarkdownBuilder()

	// Test with complex network configuration
	data := &common.CommonDevice{
		Interfaces: []common.Interface{
			{
				Name:         "wan",
				PhysicalIf:   "em0",
				Enabled:      true,
				IPAddress:    "192.168.1.1",
				Subnet:       "24",
				Gateway:      "192.168.1.254",
				MTU:          "1500",
				BlockPrivate: true,
				BlockBogons:  true,
				Description:  "WAN Interface",
			},
			{
				Name:         "lan",
				PhysicalIf:   "em1",
				Enabled:      true,
				IPAddress:    "10.0.0.1",
				Subnet:       "24",
				Gateway:      "",
				MTU:          "1500",
				BlockPrivate: false,
				BlockBogons:  false,
				Description:  "LAN Interface",
			},
			{
				Name:         "opt1",
				PhysicalIf:   "em2",
				Enabled:      true,
				IPAddress:    "172.16.0.1",
				Subnet:       "16",
				Gateway:      "",
				MTU:          "9000",
				BlockPrivate: false,
				BlockBogons:  false,
				Description:  "DMZ Interface",
			},
		},
	}

	result := builder.BuildNetworkSection(data)

	// Verify the result contains expected sections
	assert.Contains(t, result, "Network Configuration")
	assert.Contains(t, result, "Interfaces")
	assert.Contains(t, result, "Wan Interface")
	assert.Contains(t, result, "Lan Interface")
	assert.Contains(t, result, "DMZ Interface")

	// Verify interface details
	assert.Contains(t, result, "em0")
	assert.Contains(t, result, "em1")
	assert.Contains(t, result, "em2")
	assert.Contains(t, result, "192.168.1.1")
	assert.Contains(t, result, "10.0.0.1")
	assert.Contains(t, result, "172.16.0.1")
	assert.Contains(t, result, "WAN Interface")
	assert.Contains(t, result, "LAN Interface")
	assert.Contains(t, result, "DMZ Interface")
	assert.Contains(t, result, "192.168.1.254") // Gateway
	assert.Contains(t, result, "1500")          // MTU
	assert.Contains(t, result, "9000")          // MTU for opt1
}

// =============================================================================
// NAT Table Builder Tests (Issue #60)
// =============================================================================

func TestMarkdownBuilder_BuildOutboundNATTable_WithRules(t *testing.T) {
	rules := []common.NATRule{
		{
			Interfaces: []string{"wan"},
			Protocol:   "tcp",
			Source: common.RuleEndpoint{
				Address: "lan",
			},
			Destination: common.RuleEndpoint{
				Address: "any",
			},
			Target:      "wan_ip",
			Disabled:    false,
			Description: "LAN to WAN NAT",
		},
		{
			Interfaces: []string{"wan"},
			Protocol:   "",
			Source: common.RuleEndpoint{
				Address: "dmz",
			},
			Destination: common.RuleEndpoint{
				Address: "any",
			},
			Target:      "wan_ip",
			Disabled:    true,
			Description: "DMZ NAT (disabled)",
		},
	}

	tableSet := builderPkg.BuildOutboundNATTableSet(rules)

	assert.NotNil(t, tableSet)
	assert.Len(
		t,
		tableSet.Header,
		9,
	) // #, Direction, Interface, Source, Destination, Target, Protocol, Description, Status
	assert.Len(t, tableSet.Rows, 2)

	// Verify headers
	expectedHeaders := []string{
		"#",
		"Direction",
		"Interface",
		"Source",
		"Destination",
		"Target",
		"Protocol",
		"Description",
		"Status",
	}
	assert.Equal(t, expectedHeaders, tableSet.Header)

	// Verify first row (active rule)
	row := tableSet.Rows[0]
	assert.Equal(t, "1", row[0])              // #
	assert.Equal(t, "⬆️ Outbound", row[1])    // Direction
	assert.Contains(t, row[2], "wan")         // Interface (with link)
	assert.Equal(t, "lan", row[3])            // Source
	assert.Equal(t, "any", row[4])            // Destination
	assert.Equal(t, "`wan_ip`", row[5])       // Target
	assert.Equal(t, "tcp", row[6])            // Protocol
	assert.Equal(t, "LAN to WAN NAT", row[7]) // Description
	assert.Equal(t, "**Active**", row[8])     // Status

	// Verify second row (disabled rule)
	row2 := tableSet.Rows[1]
	assert.Equal(t, "2", row2[0])                  // #
	assert.Equal(t, "⬆️ Outbound", row2[1])        // Direction
	assert.Equal(t, "dmz", row2[3])                // Source
	assert.Equal(t, "any", row2[6])                // Protocol (default when empty)
	assert.Equal(t, "**Disabled**", row2[8])       // Status
	assert.Equal(t, "DMZ NAT (disabled)", row2[7]) // Description
}

func TestMarkdownBuilder_BuildOutboundNATTable_EmptyRules(t *testing.T) {
	rules := []common.NATRule{}

	tableSet := builderPkg.BuildOutboundNATTableSet(rules)

	assert.NotNil(t, tableSet)
	assert.Len(t, tableSet.Header, 9)
	assert.Len(t, tableSet.Rows, 1) // One row with "No rules configured" message

	// Verify the placeholder row
	row := tableSet.Rows[0]
	assert.Equal(t, "-", row[0])                                // #
	assert.Equal(t, "-", row[1])                                // Direction
	assert.Equal(t, "No outbound NAT rules configured", row[7]) // Description placeholder
}

func TestMarkdownBuilder_BuildOutboundNATTable_SpecialCharacters(t *testing.T) {
	rules := []common.NATRule{
		{
			Interfaces: []string{"wan"},
			Protocol:   "tcp",
			Source: common.RuleEndpoint{
				Address: "lan",
			},
			Destination: common.RuleEndpoint{
				Address: "any",
			},
			Target:      "wan_ip",
			Disabled:    false,
			Description: "Rule with | pipe and `backticks`",
		},
	}

	tableSet := builderPkg.BuildOutboundNATTableSet(rules)

	assert.NotNil(t, tableSet)
	// Description should be escaped for markdown tables
	row := tableSet.Rows[0]
	assert.Contains(t, row[7], "\\|") // Pipe should be escaped with backslash
	assert.Contains(t, row[7], "\\`") // Backticks should be escaped with backslash
}

func TestMarkdownBuilder_BuildInboundNATTable_WithRules(t *testing.T) {
	rules := []common.InboundNATRule{
		{
			Interfaces:   []string{"wan"},
			Protocol:     "tcp",
			ExternalPort: "443",
			InternalIP:   "192.168.1.10",
			InternalPort: "443",
			Priority:     10,
			Disabled:     false,
			Description:  "Web server forwarding",
		},
		{
			Interfaces:   []string{"wan"},
			Protocol:     "tcp/udp",
			ExternalPort: "8080",
			InternalIP:   "192.168.1.20",
			InternalPort: "80",
			Priority:     20,
			Disabled:     true,
			Description:  "HTTP forward (disabled)",
		},
	}

	tableSet := builderPkg.BuildInboundNATTableSet(rules)

	assert.NotNil(t, tableSet)
	assert.Len(
		t,
		tableSet.Header,
		10,
	) // #, Direction, Interface, External Port, Target IP, Target Port, Protocol, Description, Priority, Status
	assert.Len(t, tableSet.Rows, 2)

	// Verify headers
	expectedHeaders := []string{
		"#",
		"Direction",
		"Interface",
		"External Port",
		"Target IP",
		"Target Port",
		"Protocol",
		"Description",
		"Priority",
		"Status",
	}
	assert.Equal(t, expectedHeaders, tableSet.Header)

	// Verify first row (active rule)
	row := tableSet.Rows[0]
	assert.Equal(t, "1", row[0])                     // #
	assert.Equal(t, "⬇️ Inbound", row[1])            // Direction
	assert.Contains(t, row[2], "wan")                // Interface (with link)
	assert.Equal(t, "443", row[3])                   // External Port
	assert.Equal(t, "`192.168.1.10`", row[4])        // Target IP
	assert.Equal(t, "443", row[5])                   // Target Port
	assert.Equal(t, "tcp", row[6])                   // Protocol
	assert.Equal(t, "Web server forwarding", row[7]) // Description
	assert.Equal(t, "10", row[8])                    // Priority
	assert.Equal(t, "**Active**", row[9])            // Status

	// Verify second row (disabled rule)
	row2 := tableSet.Rows[1]
	assert.Equal(t, "2", row2[0])              // #
	assert.Equal(t, "⬇️ Inbound", row2[1])     // Direction
	assert.Equal(t, "8080", row2[3])           // External Port
	assert.Equal(t, "`192.168.1.20`", row2[4]) // Target IP
	assert.Equal(t, "80", row2[5])             // Target Port
	assert.Equal(t, "**Disabled**", row2[9])   // Status
}

func TestMarkdownBuilder_BuildInboundNATTable_EmptyRules(t *testing.T) {
	rules := []common.InboundNATRule{}

	tableSet := builderPkg.BuildInboundNATTableSet(rules)

	assert.NotNil(t, tableSet)
	assert.Len(t, tableSet.Header, 10)
	assert.Len(t, tableSet.Rows, 1) // One row with "No rules configured" message

	// Verify the placeholder row
	row := tableSet.Rows[0]
	assert.Equal(t, "-", row[0])                               // #
	assert.Equal(t, "-", row[1])                               // Direction
	assert.Equal(t, "No inbound NAT rules configured", row[7]) // Description placeholder
}

func TestMarkdownBuilder_BuildInboundNATTable_SpecialCharacters(t *testing.T) {
	rules := []common.InboundNATRule{
		{
			Interfaces:   []string{"wan"},
			Protocol:     "tcp",
			ExternalPort: "443",
			InternalIP:   "192.168.1.10",
			InternalPort: "443",
			Priority:     10,
			Disabled:     false,
			Description:  "Rule with | pipe and `backticks`",
		},
	}

	tableSet := builderPkg.BuildInboundNATTableSet(rules)

	assert.NotNil(t, tableSet)
	// Description should be escaped for markdown tables
	row := tableSet.Rows[0]
	assert.Contains(t, row[7], "\\|") // Pipe should be escaped with backslash
	assert.Contains(t, row[7], "\\`") // Backticks should be escaped with backslash
}

func TestMarkdownBuilder_BuildSecuritySection_WithBothNATTypes(t *testing.T) {
	builder := NewMarkdownBuilder()

	data := &common.CommonDevice{
		System: common.System{
			DisableNATReflection: true,
			PfShareForward:       true,
		},
		NAT: common.NATConfig{
			OutboundMode:       "automatic",
			ReflectionDisabled: true,
			PfShareForward:     true,
			OutboundRules: []common.NATRule{
				{
					Interfaces:  []string{"wan"},
					Protocol:    "tcp",
					Source:      common.RuleEndpoint{Address: "lan"},
					Destination: common.RuleEndpoint{Address: "any"},
					Target:      "wan_ip",
					Description: "LAN NAT",
				},
			},
			InboundRules: []common.InboundNATRule{
				{
					Interfaces:   []string{"wan"},
					Protocol:     "tcp",
					ExternalPort: "443",
					InternalIP:   "192.168.1.10",
					InternalPort: "443",
					Description:  "HTTPS forward",
				},
			},
		},
	}

	result := builder.BuildSecuritySection(data)

	// Verify outbound section exists
	assert.Contains(t, result, "Outbound NAT")
	assert.Contains(t, result, "Source Translation")
	assert.Contains(t, result, "⬆️ Outbound")
	assert.Contains(t, result, "LAN NAT")

	// Verify inbound section exists
	assert.Contains(t, result, "Inbound NAT")
	assert.Contains(t, result, "Port Forwarding")
	assert.Contains(t, result, "⬇️ Inbound")
	assert.Contains(t, result, "HTTPS forward")
	assert.Contains(t, result, "192.168.1.10")

	// Verify security warning for inbound NAT (GitHub-flavored alert)
	assert.Contains(t, result, "[!WARNING]")
	assert.Contains(t, result, "port forwarding")
}

func TestMarkdownBuilder_BuildSecuritySection_InboundSecurityWarning(t *testing.T) {
	builder := NewMarkdownBuilder()

	data := &common.CommonDevice{
		System: common.System{
			DisableNATReflection: true,
		},
		NAT: common.NATConfig{
			OutboundMode:       "automatic",
			ReflectionDisabled: true,
			InboundRules: []common.InboundNATRule{
				{
					Interfaces:   []string{"wan"},
					Protocol:     "tcp",
					ExternalPort: "22",
					InternalIP:   "192.168.1.5",
					InternalPort: "22",
					Description:  "SSH forward",
				},
			},
		},
	}

	result := builder.BuildSecuritySection(data)

	// Verify security warning is present when inbound rules exist (GitHub-flavored alert)
	assert.Contains(t, result, "[!WARNING]")
	assert.Contains(t, result, "port forwarding")
	assert.Contains(t, result, "attack surface")
}

// TestMarkdownBuilder_NATRulesWithInterfaceLinks verifies NAT rules render interface names
// as clickable markdown links pointing to interface sections (Issue #61).
func TestMarkdownBuilder_NATRulesWithInterfaceLinks(t *testing.T) {
	// Test outbound NAT with multiple interfaces
	outboundRules := []common.NATRule{
		{
			Interfaces:  []string{"wan", "lan"},
			Protocol:    "tcp",
			Source:      common.RuleEndpoint{Address: "dmz"},
			Destination: common.RuleEndpoint{Address: "any"},
			Target:      "wan_ip",
			Description: "Multi-interface NAT",
		},
		{
			Interfaces:  []string{"opt1"},
			Protocol:    "udp",
			Source:      common.RuleEndpoint{Address: "lan"},
			Destination: common.RuleEndpoint{Address: "any"},
			Target:      "opt1_ip",
			Description: "Single interface NAT",
		},
	}

	tableSet := builderPkg.BuildOutboundNATTableSet(outboundRules)

	// Verify first row has multiple interface links
	row1 := tableSet.Rows[0]
	interfaceCell := row1[2]

	// Check that interface names are formatted as links
	// FormatInterfacesAsLinks produces: [wan](#wan-interface), [lan](#lan-interface)
	assert.Contains(t, interfaceCell, "[wan]")
	assert.Contains(t, interfaceCell, "#wan-interface")
	assert.Contains(t, interfaceCell, "[lan]")
	assert.Contains(t, interfaceCell, "#lan-interface")
	assert.Contains(t, interfaceCell, ", ") // Comma separator between links

	// Verify second row has single interface link
	row2 := tableSet.Rows[1]
	interfaceCell2 := row2[2]
	assert.Contains(t, interfaceCell2, "[opt1]")
	assert.Contains(t, interfaceCell2, "#opt1-interface")
	assert.NotContains(t, interfaceCell2, ", ") // No comma for single interface

	// Test inbound NAT with interface links
	inboundRules := []common.InboundNATRule{
		{
			Interfaces:   []string{"wan"},
			Protocol:     "tcp",
			ExternalPort: "443",
			InternalIP:   "192.168.1.10",
			InternalPort: "443",
			Description:  "HTTPS forward",
		},
		{
			Interfaces:   []string{"wan", "opt2"},
			Protocol:     "tcp",
			ExternalPort: "8080",
			InternalIP:   "192.168.1.20",
			InternalPort: "80",
			Description:  "HTTP multi-interface",
		},
	}

	inboundTableSet := builderPkg.BuildInboundNATTableSet(inboundRules)

	// Verify inbound rule interface links
	inRow1 := inboundTableSet.Rows[0]
	inInterfaceCell := inRow1[2]
	assert.Contains(t, inInterfaceCell, "[wan]")
	assert.Contains(t, inInterfaceCell, "#wan-interface")

	// Verify multi-interface inbound rule
	inRow2 := inboundTableSet.Rows[1]
	inInterfaceCell2 := inRow2[2]
	assert.Contains(t, inInterfaceCell2, "[wan]")
	assert.Contains(t, inInterfaceCell2, "#wan-interface")
	assert.Contains(t, inInterfaceCell2, "[opt2]")
	assert.Contains(t, inInterfaceCell2, "#opt2-interface")
	assert.Contains(t, inInterfaceCell2, ", ") // Comma separator between links
}

// TestMarkdownBuilder_NATRulesEmptyInterfaceList verifies NAT rules with empty
// interface lists render gracefully (Issue #61 edge case).
func TestMarkdownBuilder_NATRulesEmptyInterfaceList(t *testing.T) {
	// NAT rule with empty interface list
	rules := []common.NATRule{
		{
			Interfaces:  []string{},
			Protocol:    "tcp",
			Source:      common.RuleEndpoint{Address: "lan"},
			Destination: common.RuleEndpoint{Address: "any"},
			Target:      "wan_ip",
			Description: "NAT without interface",
		},
	}

	tableSet := builderPkg.BuildOutboundNATTableSet(rules)

	// Empty interface list should render as empty string, not cause panic
	row := tableSet.Rows[0]
	assert.Empty(t, row[2]) // Interface column should be empty
	assert.Equal(t, "NAT without interface", row[7])
}

func TestMarkdownBuilder_BuildIDSSection_Enabled(t *testing.T) {
	builder := NewMarkdownBuilder()

	data := &common.CommonDevice{
		IDS: &common.IDSConfig{
			Enabled:           true,
			IPSMode:           true,
			Interfaces:        []string{"wan", "lan"},
			HomeNetworks:      []string{"192.168.1.0/24", "10.0.0.0/8"},
			Detect:            common.IDSDetect{Profile: "medium"},
			MPMAlgo:           "ac",
			Promiscuous:       false,
			SyslogEnabled:     true,
			SyslogEveEnabled:  true,
			LogPayload:        "1",
			AlertLogrotate:    "W0D23",
			AlertSaveLogs:     "4",
			DefaultPacketSize: "1518",
		},
	}

	result := builder.BuildIDSSection(data)

	assert.Contains(t, result, "Intrusion Detection System (IDS/Suricata)")
	assert.Contains(t, result, "Enabled")
	assert.Contains(t, result, "IPS")
	assert.Contains(t, result, "medium")
	assert.Contains(t, result, "ac")
	assert.Contains(t, result, "wan")
	assert.Contains(t, result, "lan")
	assert.Contains(t, result, "192.168.1.0/24")
	assert.Contains(t, result, "10.0.0.0/8")
	assert.Contains(t, result, "Syslog")
	assert.Contains(t, result, "EVE Syslog")
	assert.Contains(t, result, "Log Rotation")
	assert.Contains(t, result, "Log Retention")
	assert.Contains(t, result, "1518")
	// IPS mode note
	assert.Contains(t, result, "IPS mode is active")
	// EVE syslog note
	assert.Contains(t, result, "EVE JSON logging is enabled")
}

func TestMarkdownBuilder_BuildIDSSection_IDSMode(t *testing.T) {
	builder := NewMarkdownBuilder()

	data := &common.CommonDevice{
		IDS: &common.IDSConfig{
			Enabled:    true,
			IPSMode:    false,
			Interfaces: []string{"opt1"},
		},
	}

	result := builder.BuildIDSSection(data)

	assert.Contains(t, result, "IDS")
	assert.Contains(t, result, "Consider enabling IPS mode")
}

func TestMarkdownBuilder_BuildIDSSection_Disabled(t *testing.T) {
	builder := NewMarkdownBuilder()

	data := &common.CommonDevice{
		IDS: &common.IDSConfig{
			Enabled: false,
		},
	}

	result := builder.BuildIDSSection(data)

	assert.Empty(t, result)
}

func TestMarkdownBuilder_BuildIDSSection_NilIDS(t *testing.T) {
	builder := NewMarkdownBuilder()

	data := &common.CommonDevice{}

	result := builder.BuildIDSSection(data)

	assert.Empty(t, result)
}

func TestMarkdownBuilder_BuildSecuritySection_IncludesIDS(t *testing.T) {
	builder := NewMarkdownBuilder()

	data := &common.CommonDevice{
		IDS: &common.IDSConfig{
			Enabled:    true,
			IPSMode:    true,
			Interfaces: []string{"opt2"},
		},
	}

	result := builder.BuildSecuritySection(data)

	assert.Contains(t, result, "Security Configuration")
	assert.Contains(t, result, "Intrusion Detection System (IDS/Suricata)")
}
