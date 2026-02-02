package converter

import (
	"context"
	"strings"
	"testing"

	builderPkg "github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
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
	data.System.DisableNATReflection = "1" // Override to disable NAT reflection

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
	data := &model.OpnSenseDocument{
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					If:          "em0",
					Enable:      "1",
					IPAddr:      "192.168.1.1",
					Subnet:      "24",
					Gateway:     "192.168.1.254",
					MTU:         "1500",
					BlockPriv:   "1",
					BlockBogons: "1",
					Descr:       "WAN Interface",
				},
				"lan": {
					If:          "em1",
					Enable:      "1",
					IPAddr:      "10.0.0.1",
					Subnet:      "24",
					Gateway:     "",
					MTU:         "1500",
					BlockPriv:   "0",
					BlockBogons: "0",
					Descr:       "LAN Interface",
				},
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
	data := &model.OpnSenseDocument{
		Nat: model.Nat{
			Outbound: model.Outbound{
				Mode: "automatic",
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{
					Type:       "pass",
					Descr:      "Allow LAN to WAN",
					Interface:  model.InterfaceList{"lan"},
					IPProtocol: "inet",
					Protocol:   "tcp",
					Source: model.Source{
						Network: "lan",
					},
					Destination: model.Destination{
						Network: "any",
					},
					Target:     "",
					SourcePort: "",
					Disabled:   "",
				},
				{
					Type:       "block",
					Descr:      "Block all",
					Interface:  model.InterfaceList{"wan"},
					IPProtocol: "inet",
					Protocol:   "any",
					Source: model.Source{
						Network: "any",
					},
					Destination: model.Destination{
						Network: "any",
					},
					Target:     "",
					SourcePort: "",
					Disabled:   "",
				},
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
	data := &model.OpnSenseDocument{
		Dhcpd: model.Dhcpd{
			Items: map[string]model.DhcpdInterface{
				"lan": {
					Enable: "1",
					Range: model.Range{
						From: "10.0.0.100",
						To:   "10.0.0.200",
					},
				},
				"wan": {
					Enable: "1",
				},
			},
		},
		Unbound: model.Unbound{
			Enable: "1",
		},
		Snmpd: model.Snmpd{
			SysLocation: "Data Center",
			SysContact:  "admin@example.com",
			ROCommunity: "public",
		},
		Ntpd: model.Ntpd{
			Prefer: "pool.ntp.org",
		},
		LoadBalancer: model.LoadBalancer{
			MonitorType: []model.MonitorType{
				{
					Name:  "http-monitor",
					Type:  "http",
					Descr: "HTTP Health Check",
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
	rules := []model.Rule{
		{
			Type:       "pass",
			Descr:      "Allow LAN to WAN",
			Interface:  model.InterfaceList{"lan"},
			IPProtocol: "inet",
			Protocol:   "tcp",
			Source: model.Source{
				Network: "lan",
			},
			Destination: model.Destination{
				Network: "any",
			},
			Target:     "",
			SourcePort: "80",
			Disabled:   "",
		},
	}

	tableSet := builderPkg.BuildFirewallRulesTableSet(rules)

	assert.NotNil(t, tableSet)
	assert.Len(t, tableSet.Header, 11)
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
	assert.Equal(t, "✓", row[9])                 // Enabled
	assert.Equal(t, "Allow LAN to WAN", row[10]) // Description
}

func TestMarkdownBuilder_BuildInterfaceTable(t *testing.T) {
	interfaces := model.Interfaces{
		Items: map[string]model.Interface{
			"wan": {
				If:     "em0",
				Enable: "1",
				IPAddr: "192.168.1.1",
				Subnet: "24",
				Descr:  "WAN Interface",
			},
			"lan": {
				If:     "em1",
				Enable: "1",
				IPAddr: "10.0.0.1",
				Subnet: "24",
				Descr:  "LAN Interface",
			},
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
	users := []model.User{
		{
			Name:      "admin",
			Descr:     "Administrator",
			Groupname: "wheel",
			Scope:     "system",
		},
		{
			Name:      "user1",
			Descr:     "Regular User",
			Groupname: "users",
			Scope:     "local",
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
	groups := []model.Group{
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
	sysctl := []model.SysctlItem{
		{
			Tunable: "net.inet.ip.forwarding",
			Value:   "1",
			Descr:   "Enable IP forwarding",
		},
		{
			Tunable: "net.inet.tcp.always_keepalive",
			Value:   "0",
			Descr:   "Disable TCP keepalive",
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

	data := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-host",
			Domain:   "test.local",
			Firmware: model.Firmware{
				Version: "23.1.1",
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					If:     "em0",
					Enable: "1",
					IPAddr: "192.168.1.1",
					Subnet: "24",
				},
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

	data := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-host",
			Domain:   "test.local",
			Firmware: model.Firmware{
				Version: "23.1.1",
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					If:     "em0",
					Enable: "1",
					IPAddr: "192.168.1.1",
					Subnet: "24",
				},
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
	assert.Equal(t, ErrNilOpnSenseDocument, err)
}

func TestMarkdownBuilder_BuildComprehensiveReport_NilData(t *testing.T) {
	builder := NewMarkdownBuilder()

	result, err := builder.BuildComprehensiveReport(nil)

	require.Error(t, err)
	assert.Empty(t, result)
	assert.Equal(t, ErrNilOpnSenseDocument, err)
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

func TestFormatBooleanInverted(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "true_value",
			input:    "1",
			expected: "✗",
		},
		{
			name:     "true_string",
			input:    "true",
			expected: "✗",
		},
		{
			name:     "on_value",
			input:    "on",
			expected: "✗",
		},
		{
			name:     "false_value",
			input:    "0",
			expected: "✓",
		},
		{
			name:     "false_string",
			input:    "false",
			expected: "✓",
		},
		{
			name:     "empty_string",
			input:    "",
			expected: "✓",
		},
		{
			name:     "random_string",
			input:    "random",
			expected: "✓",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatters.FormatBooleanInverted(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildFirewallRulesTable_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		rules []model.Rule
	}{
		{
			name:  "empty_rules",
			rules: []model.Rule{},
		},
		{
			name: "rules_with_empty_networks",
			rules: []model.Rule{
				{
					Type:        "pass",
					Interface:   model.InterfaceList{"lan"},
					IPProtocol:  "inet",
					Protocol:    "tcp",
					Source:      model.Source{Network: ""},
					Destination: model.Destination{Network: ""},
					Descr:       "Test rule",
				},
			},
		},
		{
			name: "rules_with_nil_interface",
			rules: []model.Rule{
				{
					Type:        "pass",
					Interface:   nil,
					IPProtocol:  "inet",
					Protocol:    "tcp",
					Source:      model.Source{Network: "lan"},
					Destination: model.Destination{Network: "any"},
					Descr:       "Test rule",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builderPkg.BuildFirewallRulesTableSet(tt.rules)
			assert.NotNil(t, result)
			assert.Len(t, result.Header, 11) // Should have 11 headers
		})
	}
}

func TestBuildStandardReport_EdgeCases(t *testing.T) {
	builder := NewMarkdownBuilder()

	tests := []struct {
		name string
		data *model.OpnSenseDocument
	}{
		{
			name: "empty_system_config",
			data: &model.OpnSenseDocument{
				System: model.System{},
			},
		},
		{
			name: "minimal_data",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
					Domain:   "test.local",
				},
			},
		},
		{
			name: "data_with_empty_interfaces",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{},
				},
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
		data *model.OpnSenseDocument
	}{
		{
			name: "no_nat_config",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
					Domain:   "test.local",
				},
			},
		},
		{
			name: "no_firewall_rules",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				Filter: model.Filter{
					Rule: []model.Rule{},
				},
			},
		},
		{
			name: "nat_without_outbound",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				Nat: model.Nat{
					Outbound: model.Outbound{},
				},
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
		data *model.OpnSenseDocument
	}{
		{
			name: "no_dhcp_config",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
					Domain:   "test.local",
				},
			},
		},
		{
			name: "no_unbound_config",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				Unbound: model.Unbound{},
			},
		},
		{
			name: "no_snmp_config",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				Snmpd: model.Snmpd{},
			},
		},
		{
			name: "no_ntpd_config",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				Ntpd: model.Ntpd{},
			},
		},
		{
			name: "no_load_balancer_config",
			data: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "test",
					Domain:   "test.local",
				},
				LoadBalancer: model.LoadBalancer{},
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
		data *model.OpnSenseDocument
	}{
		{
			name: "empty_opnsense",
			data: &model.OpnSenseDocument{},
		},
		{
			name: "minimal_opnsense",
			data: &model.OpnSenseDocument{
				System: model.System{
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
	data := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-host",
			Domain:   "test.local",
			Firmware: model.Firmware{
				Version: "23.1.1",
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					If:     "em0",
					Enable: "1",
					IPAddr: "192.168.1.1",
					Subnet: "24",
				},
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

	data := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-host",
			Domain:   "test.local",
			Firmware: model.Firmware{
				Version: "23.1.1",
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					If:     "em0",
					Enable: "1",
					IPAddr: "192.168.1.1",
					Subnet: "24",
				},
				"lan": {
					If:     "em1",
					Enable: "1",
					IPAddr: "10.0.0.1",
					Subnet: "24",
				},
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

	data := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-host",
			Domain:   "test.local",
			Firmware: model.Firmware{
				Version: "23.1.1",
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					If:     "em0",
					Enable: "1",
					IPAddr: "192.168.1.1",
					Subnet: "24",
				},
				"lan": {
					If:     "em1",
					Enable: "1",
					IPAddr: "10.0.0.1",
					Subnet: "24",
				},
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
	data := &model.OpnSenseDocument{
		System: model.System{
			DisableNATReflection: "0", // NAT reflection enabled
			PfShareForward:       1,
		},
		Nat: model.Nat{
			Outbound: model.Outbound{
				Mode: "automatic",
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{
					Type:       "pass",
					Descr:      "Test rule",
					Interface:  model.InterfaceList{"lan"},
					IPProtocol: "inet",
					Protocol:   "tcp",
					Source: model.Source{
						Network: "lan",
					},
					Destination: model.Destination{
						Network: "any",
					},
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
	data := &model.OpnSenseDocument{
		LoadBalancer: model.LoadBalancer{
			MonitorType: []model.MonitorType{
				{
					Name:  "http-monitor",
					Type:  "http",
					Descr: "HTTP Health Check",
				},
				{
					Name:  "tcp-monitor",
					Type:  "tcp",
					Descr: "TCP Health Check",
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
	data := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-host",
			Domain:   "test.local",
			User: []model.User{
				{
					Name:      "admin",
					Descr:     "Administrator",
					Groupname: "wheel",
					Scope:     "system",
				},
				{
					Name:      "user1",
					Descr:     "Regular User",
					Groupname: "users",
					Scope:     "local",
				},
			},
		},
		Sysctl: []model.SysctlItem{
			{
				Tunable: "net.inet.ip.forwarding",
				Value:   "1",
				Descr:   "Enable IP forwarding",
			},
			{
				Tunable: "net.inet.tcp.always_keepalive",
				Value:   "0",
				Descr:   "Disable TCP keepalive",
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
	data := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-host",
			Domain:   "test.local",
			Group: []model.Group{
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
	rules := []model.Rule{
		{
			Type:       "pass",
			Descr:      "Allow HTTPS",
			Interface:  model.InterfaceList{"wan"},
			IPProtocol: "inet",
			Protocol:   "tcp",
			Source: model.Source{
				Network: "any",
			},
			Destination: model.Destination{
				Network: "lan",
			},
			Target:     "lan",
			SourcePort: "443",
			Disabled:   "1", // Disabled rule
		},
		{
			Type:       "block",
			Descr:      "Block SSH",
			Interface:  model.InterfaceList{"wan", "lan"},
			IPProtocol: "inet6",
			Protocol:   "tcp",
			Source: model.Source{
				Network: "lan",
			},
			Destination: model.Destination{
				Network: "wan",
			},
			Target:     "",
			SourcePort: "22",
			Disabled:   "",
		},
	}

	tableSet := builderPkg.BuildFirewallRulesTableSet(rules)

	assert.NotNil(t, tableSet)
	assert.Len(t, tableSet.Header, 11)
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
	assert.Equal(t, "✗", row1[9])            // Enabled (disabled)
	assert.Equal(t, "Allow HTTPS", row1[10]) // Description

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
	assert.Equal(t, "✓", row2[9])          // Enabled
	assert.Equal(t, "Block SSH", row2[10]) // Description
}

func TestMarkdownBuilder_BuildInterfaceTable_WithComplexInterfaces(t *testing.T) {
	// Test with complex interface configurations
	interfaces := model.Interfaces{
		Items: map[string]model.Interface{
			"wan": {
				If:          "em0",
				Enable:      "1",
				IPAddr:      "192.168.1.1",
				Subnet:      "24",
				Gateway:     "192.168.1.254",
				MTU:         "1500",
				BlockPriv:   "1",
				BlockBogons: "1",
				Descr:       "WAN Interface",
			},
			"lan": {
				If:          "em1",
				Enable:      "0", // Disabled interface
				IPAddr:      "10.0.0.1",
				Subnet:      "24",
				Gateway:     "",
				MTU:         "1500",
				BlockPriv:   "0",
				BlockBogons: "0",
				Descr:       "LAN Interface",
			},
			"opt1": {
				If:          "em2",
				Enable:      "1",
				IPAddr:      "172.16.0.1",
				Subnet:      "16",
				Gateway:     "",
				MTU:         "9000",
				BlockPriv:   "0",
				BlockBogons: "0",
				Descr:       "DMZ Interface",
			},
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

func TestFormatStructBoolean(t *testing.T) {
	// Test with empty struct
	result := formatters.FormatStructBoolean(struct{}{})
	assert.Equal(t, "✓", result)
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
func createComprehensiveTestData() *model.OpnSenseDocument {
	return &model.OpnSenseDocument{
		System: model.System{
			Hostname:                      "test-host",
			Domain:                        "test.local",
			Optimization:                  "normal",
			Timezone:                      "UTC",
			Language:                      "en_US",
			DNSAllowOverride:              1,
			NextUID:                       1000,
			NextGID:                       1000,
			TimeServers:                   "pool.ntp.org",
			DNSServer:                     "8.8.8.8",
			UseVirtualTerminal:            1,
			DisableVLANHWFilter:           0,
			DisableChecksumOffloading:     0,
			DisableSegmentationOffloading: 0,
			DisableLargeReceiveOffloading: 0,
			IPv6Allow:                     "1",
			DisableNATReflection:          "0", // NAT reflection enabled
			PowerdACMode:                  "adaptive",
			PowerdBatteryMode:             "minimum",
			PowerdNormalMode:              "adaptive",
			PfShareForward:                1,
			LbUseSticky:                   0,
			RrdBackup:                     1,
			NetflowBackup:                 0,
			WebGUI: model.WebGUIConfig{
				Protocol: "https",
			},
			SSH: model.SSHConfig{
				Group: "wheel",
			},
			Firmware: model.Firmware{
				Version: "23.1.1",
			},
			Bogons: struct {
				Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
			}{
				Interval: "daily",
			},
			User: []model.User{
				{
					Name:      "admin",
					Descr:     "Administrator",
					Groupname: "wheel",
					Scope:     "system",
				},
			},
			Group: []model.Group{
				{
					Name:        "wheel",
					Description: "Wheel group",
					Scope:       "system",
				},
			},
		},
		Sysctl: []model.SysctlItem{
			{
				Tunable: "net.inet.ip.forwarding",
				Value:   "1",
				Descr:   "Enable IP forwarding",
			},
		},
	}
}

func TestMarkdownBuilder_BuildNetworkSection_WithComplexInterfaces(t *testing.T) {
	builder := NewMarkdownBuilder()

	// Test with complex network configuration
	data := &model.OpnSenseDocument{
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					If:          "em0",
					Enable:      "1",
					IPAddr:      "192.168.1.1",
					Subnet:      "24",
					Gateway:     "192.168.1.254",
					MTU:         "1500",
					BlockPriv:   "1",
					BlockBogons: "1",
					Descr:       "WAN Interface",
				},
				"lan": {
					If:          "em1",
					Enable:      "1",
					IPAddr:      "10.0.0.1",
					Subnet:      "24",
					Gateway:     "",
					MTU:         "1500",
					BlockPriv:   "0",
					BlockBogons: "0",
					Descr:       "LAN Interface",
				},
				"opt1": {
					If:          "em2",
					Enable:      "1",
					IPAddr:      "172.16.0.1",
					Subnet:      "16",
					Gateway:     "",
					MTU:         "9000",
					BlockPriv:   "0",
					BlockBogons: "0",
					Descr:       "DMZ Interface",
				},
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
	rules := []model.NATRule{
		{
			Interface: model.InterfaceList{"wan"},
			Protocol:  "tcp",
			Source: model.Source{
				Network: "lan",
			},
			Destination: model.Destination{
				Any: "any",
			},
			Target:   "wan_ip",
			Disabled: "",
			Descr:    "LAN to WAN NAT",
		},
		{
			Interface: model.InterfaceList{"wan"},
			Protocol:  "",
			Source: model.Source{
				Network: "dmz",
			},
			Destination: model.Destination{
				Network: "any",
			},
			Target:   "wan_ip",
			Disabled: "1",
			Descr:    "DMZ NAT (disabled)",
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
	rules := []model.NATRule{}

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
	rules := []model.NATRule{
		{
			Interface: model.InterfaceList{"wan"},
			Protocol:  "tcp",
			Source: model.Source{
				Network: "lan",
			},
			Destination: model.Destination{
				Any: "any",
			},
			Target:   "wan_ip",
			Disabled: "",
			Descr:    "Rule with | pipe and `backticks`",
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
	rules := []model.InboundRule{
		{
			Interface:    model.InterfaceList{"wan"},
			Protocol:     "tcp",
			ExternalPort: "443",
			InternalIP:   "192.168.1.10",
			InternalPort: "443",
			Priority:     10,
			Disabled:     "",
			Descr:        "Web server forwarding",
		},
		{
			Interface:    model.InterfaceList{"wan"},
			Protocol:     "tcp/udp",
			ExternalPort: "8080",
			InternalIP:   "192.168.1.20",
			InternalPort: "80",
			Priority:     20,
			Disabled:     "1",
			Descr:        "HTTP forward (disabled)",
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
	rules := []model.InboundRule{}

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
	rules := []model.InboundRule{
		{
			Interface:    model.InterfaceList{"wan"},
			Protocol:     "tcp",
			ExternalPort: "443",
			InternalIP:   "192.168.1.10",
			InternalPort: "443",
			Priority:     10,
			Disabled:     "",
			Descr:        "Rule with | pipe and `backticks`",
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

	data := &model.OpnSenseDocument{
		System: model.System{
			DisableNATReflection: "yes",
			PfShareForward:       1,
		},
		Nat: model.Nat{
			Outbound: model.Outbound{
				Mode: "automatic",
				Rule: []model.NATRule{
					{
						Interface:   model.InterfaceList{"wan"},
						Protocol:    "tcp",
						Source:      model.Source{Network: "lan"},
						Destination: model.Destination{Any: "any"},
						Target:      "wan_ip",
						Descr:       "LAN NAT",
					},
				},
			},
			Inbound: []model.InboundRule{
				{
					Interface:    model.InterfaceList{"wan"},
					Protocol:     "tcp",
					ExternalPort: "443",
					InternalIP:   "192.168.1.10",
					InternalPort: "443",
					Descr:        "HTTPS forward",
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

	data := &model.OpnSenseDocument{
		System: model.System{
			DisableNATReflection: "yes",
		},
		Nat: model.Nat{
			Outbound: model.Outbound{
				Mode: "automatic",
			},
			Inbound: []model.InboundRule{
				{
					Interface:    model.InterfaceList{"wan"},
					Protocol:     "tcp",
					ExternalPort: "22",
					InternalIP:   "192.168.1.5",
					InternalPort: "22",
					Descr:        "SSH forward",
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
	outboundRules := []model.NATRule{
		{
			Interface:   model.InterfaceList{"wan", "lan"},
			Protocol:    "tcp",
			Source:      model.Source{Network: "dmz"},
			Destination: model.Destination{Any: "any"},
			Target:      "wan_ip",
			Descr:       "Multi-interface NAT",
		},
		{
			Interface:   model.InterfaceList{"opt1"},
			Protocol:    "udp",
			Source:      model.Source{Network: "lan"},
			Destination: model.Destination{Network: "any"},
			Target:      "opt1_ip",
			Descr:       "Single interface NAT",
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
	inboundRules := []model.InboundRule{
		{
			Interface:    model.InterfaceList{"wan"},
			Protocol:     "tcp",
			ExternalPort: "443",
			InternalIP:   "192.168.1.10",
			InternalPort: "443",
			Descr:        "HTTPS forward",
		},
		{
			Interface:    model.InterfaceList{"wan", "opt2"},
			Protocol:     "tcp",
			ExternalPort: "8080",
			InternalIP:   "192.168.1.20",
			InternalPort: "80",
			Descr:        "HTTP multi-interface",
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
	rules := []model.NATRule{
		{
			Interface:   model.InterfaceList{},
			Protocol:    "tcp",
			Source:      model.Source{Network: "lan"},
			Destination: model.Destination{Any: "any"},
			Target:      "wan_ip",
			Descr:       "NAT without interface",
		},
	}

	tableSet := builderPkg.BuildOutboundNATTableSet(rules)

	// Empty interface list should render as empty string, not cause panic
	row := tableSet.Rows[0]
	assert.Empty(t, row[2]) // Interface column should be empty
	assert.Equal(t, "NAT without interface", row[7])
}
