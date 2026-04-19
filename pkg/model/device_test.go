package model_test

import (
	"encoding/json"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestDeviceType_Constants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dt       common.DeviceType
		expected string
	}{
		{"OPNsense", common.DeviceTypeOPNsense, "opnsense"},
		{"pfSense", common.DeviceTypePfSense, "pfsense"},
		{"Unknown", common.DeviceTypeUnknown, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if string(tt.dt) != tt.expected {
				t.Errorf("DeviceType %s = %q, want %q", tt.name, tt.dt, tt.expected)
			}
		})
	}
}

func TestDeviceType_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dt   common.DeviceType
		want bool
	}{
		{"OPNsense is valid", common.DeviceTypeOPNsense, true},
		{"pfSense is valid", common.DeviceTypePfSense, true},
		{"Unknown is invalid", common.DeviceTypeUnknown, false},
		{"empty is invalid", common.DeviceType(""), false},
		{"arbitrary string is invalid", common.DeviceType("fortinet"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.dt.IsValid(); got != tt.want {
				t.Errorf("DeviceType(%q).IsValid() = %v, want %v", tt.dt, got, tt.want)
			}
		})
	}
}

func TestDeviceType_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dt   common.DeviceType
		want string
	}{
		{"OPNsense", common.DeviceTypeOPNsense, "opnsense"},
		{"pfSense", common.DeviceTypePfSense, "pfsense"},
		{"Unknown", common.DeviceTypeUnknown, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.dt.String(); got != tt.want {
				t.Errorf("DeviceType(%q).String() = %q, want %q", tt.dt, got, tt.want)
			}
		})
	}
}

func TestDeviceType_DisplayName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dt   common.DeviceType
		want string
	}{
		{"OPNsense", common.DeviceTypeOPNsense, "OPNsense"},
		{"pfSense", common.DeviceTypePfSense, "pfSense"},
		{"Unknown", common.DeviceTypeUnknown, "Device"},
		{"empty string", common.DeviceType(""), "Device"},
		{"arbitrary unrecognized value", common.DeviceType("fortinet"), "Device"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.dt.DisplayName(); got != tt.want {
				t.Errorf("DeviceType(%q).DisplayName() = %q, want %q", tt.dt, got, tt.want)
			}
		})
	}
}

func TestCommonDevice_NATSummary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		device common.CommonDevice
		want   common.NATSummary
	}{
		{
			name:   "empty device returns empty summary",
			device: common.CommonDevice{},
			want:   common.NATSummary{},
		},
		{
			name: "populated NAT fields propagate",
			device: common.CommonDevice{
				NAT: common.NATConfig{
					OutboundMode:       common.OutboundHybrid,
					ReflectionDisabled: true,
					PfShareForward:     true,
					OutboundRules: []common.NATRule{
						{UUID: "r1", Description: "outbound 1"},
					},
					InboundRules: []common.InboundNATRule{
						{UUID: "r2", Description: "inbound 1"},
					},
				},
			},
			want: common.NATSummary{
				Mode:               "hybrid",
				ReflectionDisabled: true,
				PfShareForward:     true,
				OutboundRules: []common.NATRule{
					{UUID: "r1", Description: "outbound 1"},
				},
				InboundRules: []common.InboundNATRule{
					{UUID: "r2", Description: "inbound 1"},
				},
			},
		},
		{
			name: "BiNATEnabled not included in summary",
			device: common.CommonDevice{
				NAT: common.NATConfig{
					OutboundMode: common.OutboundAutomatic,
					BiNATEnabled: true,
				},
			},
			want: common.NATSummary{
				Mode: "automatic",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.device.NATSummary()

			if got.Mode != tt.want.Mode {
				t.Errorf("NATSummary().Mode = %q, want %q", got.Mode, tt.want.Mode)
			}
			if got.ReflectionDisabled != tt.want.ReflectionDisabled {
				t.Errorf(
					"NATSummary().ReflectionDisabled = %v, want %v",
					got.ReflectionDisabled,
					tt.want.ReflectionDisabled,
				)
			}
			if got.PfShareForward != tt.want.PfShareForward {
				t.Errorf("NATSummary().PfShareForward = %v, want %v", got.PfShareForward, tt.want.PfShareForward)
			}
			if len(got.OutboundRules) != len(tt.want.OutboundRules) {
				t.Errorf(
					"NATSummary().OutboundRules len = %d, want %d",
					len(got.OutboundRules),
					len(tt.want.OutboundRules),
				)
			}
			if len(got.InboundRules) != len(tt.want.InboundRules) {
				t.Errorf(
					"NATSummary().InboundRules len = %d, want %d",
					len(got.InboundRules),
					len(tt.want.InboundRules),
				)
			}
		})
	}
}

func TestNATSummary_CloneIsolation(t *testing.T) {
	t.Parallel()

	device := common.CommonDevice{
		NAT: common.NATConfig{
			OutboundRules: []common.NATRule{{UUID: "r1"}},
			InboundRules:  []common.InboundNATRule{{UUID: "r2"}},
		},
	}

	summary := device.NATSummary()

	// Mutate the summary slices — original device must be unaffected.
	summary.OutboundRules = append(summary.OutboundRules, common.NATRule{UUID: "added"})
	summary.InboundRules = append(summary.InboundRules, common.InboundNATRule{UUID: "added"})

	if len(device.NAT.OutboundRules) != 1 {
		t.Errorf("OutboundRules len = %d after summary mutation, want 1", len(device.NAT.OutboundRules))
	}
	if len(device.NAT.InboundRules) != 1 {
		t.Errorf("InboundRules len = %d after summary mutation, want 1", len(device.NAT.InboundRules))
	}
}

func TestCommonDevice_NATSummary_NilReceiver(t *testing.T) {
	t.Parallel()

	var device *common.CommonDevice
	summary := device.NATSummary()

	if summary.Mode != "" {
		t.Errorf("NATSummary().Mode = %q on nil receiver, want empty", summary.Mode)
	}
	if len(summary.OutboundRules) != 0 {
		t.Errorf("NATSummary().OutboundRules len = %d on nil receiver, want 0", len(summary.OutboundRules))
	}
	if len(summary.InboundRules) != 0 {
		t.Errorf("NATSummary().InboundRules len = %d on nil receiver, want 0", len(summary.InboundRules))
	}
}

func TestCommonDevice_HasNATConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		device common.CommonDevice
		want   bool
	}{
		{
			name:   "zero-value NATConfig returns false",
			device: common.CommonDevice{},
			want:   false,
		},
		{
			name: "OutboundMode set returns true",
			device: common.CommonDevice{
				NAT: common.NATConfig{OutboundMode: common.OutboundHybrid},
			},
			want: true,
		},
		{
			name: "OutboundRules present returns true",
			device: common.CommonDevice{
				NAT: common.NATConfig{OutboundRules: []common.NATRule{{UUID: "r1"}}},
			},
			want: true,
		},
		{
			name: "InboundRules present returns true",
			device: common.CommonDevice{
				NAT: common.NATConfig{InboundRules: []common.InboundNATRule{{UUID: "r1"}}},
			},
			want: true,
		},
		{
			name: "ReflectionDisabled returns true",
			device: common.CommonDevice{
				NAT: common.NATConfig{ReflectionDisabled: true},
			},
			want: true,
		},
		{
			name: "PfShareForward returns true",
			device: common.CommonDevice{
				NAT: common.NATConfig{PfShareForward: true},
			},
			want: true,
		},
		{
			name: "BiNATEnabled returns true",
			device: common.CommonDevice{
				NAT: common.NATConfig{BiNATEnabled: true},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.device.HasNATConfig(); got != tt.want {
				t.Errorf("HasNATConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommonDevice_HasNATConfig_NilReceiver(t *testing.T) {
	t.Parallel()

	var device *common.CommonDevice
	if device.HasNATConfig() {
		t.Error("HasNATConfig() on nil receiver should return false")
	}
}

func TestNATConfig_HasData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  common.NATConfig
		want bool
	}{
		{
			name: "zero-value returns false",
			cfg:  common.NATConfig{},
			want: false,
		},
		{
			name: "OutboundMode set returns true",
			cfg:  common.NATConfig{OutboundMode: common.OutboundHybrid},
			want: true,
		},
		{
			name: "OutboundRules present returns true",
			cfg:  common.NATConfig{OutboundRules: []common.NATRule{{UUID: "r1"}}},
			want: true,
		},
		{
			name: "InboundRules present returns true",
			cfg:  common.NATConfig{InboundRules: []common.InboundNATRule{{UUID: "r1"}}},
			want: true,
		},
		{
			name: "ReflectionDisabled returns true",
			cfg:  common.NATConfig{ReflectionDisabled: true},
			want: true,
		},
		{
			name: "PfShareForward returns true",
			cfg:  common.NATConfig{PfShareForward: true},
			want: true,
		},
		{
			name: "BiNATEnabled returns true",
			cfg:  common.NATConfig{BiNATEnabled: true},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.cfg.HasData(); got != tt.want {
				t.Errorf("NATConfig.HasData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommonDevice_HasInterfaces(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		device common.CommonDevice
		want   bool
	}{
		{
			name:   "empty interfaces returns false",
			device: common.CommonDevice{},
			want:   false,
		},
		{
			name: "populated interfaces returns true",
			device: common.CommonDevice{
				Interfaces: []common.Interface{{Name: "wan"}},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.device.HasInterfaces(); got != tt.want {
				t.Errorf("HasInterfaces() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommonDevice_HasInterfaces_NilReceiver(t *testing.T) {
	t.Parallel()

	var device *common.CommonDevice
	if device.HasInterfaces() {
		t.Error("HasInterfaces() on nil receiver should return false")
	}
}

func TestCommonDevice_HasVLANs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		device common.CommonDevice
		want   bool
	}{
		{
			name:   "empty VLANs returns false",
			device: common.CommonDevice{},
			want:   false,
		},
		{
			name: "populated VLANs returns true",
			device: common.CommonDevice{
				VLANs: []common.VLAN{{VLANIf: "vlan10", Tag: "10"}},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.device.HasVLANs(); got != tt.want {
				t.Errorf("HasVLANs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommonDevice_HasVLANs_NilReceiver(t *testing.T) {
	t.Parallel()

	var device *common.CommonDevice
	if device.HasVLANs() {
		t.Error("HasVLANs() on nil receiver should return false")
	}
}

func TestCommonDevice_HasDHCP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		device common.CommonDevice
		want   bool
	}{
		{
			name:   "empty DHCP returns false",
			device: common.CommonDevice{},
			want:   false,
		},
		{
			name: "populated legacy DHCP returns true",
			device: common.CommonDevice{
				DHCP: []common.DHCPScope{{Interface: "lan"}},
			},
			want: true,
		},
		{
			name: "Kea DHCP scope in unified slice returns true",
			device: common.CommonDevice{
				DHCP: []common.DHCPScope{{Source: common.DHCPSourceKea, Description: "LAN subnet"}},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.device.HasDHCP(); got != tt.want {
				t.Errorf("HasDHCP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommonDevice_HasDHCP_NilReceiver(t *testing.T) {
	t.Parallel()

	var device *common.CommonDevice
	if device.HasDHCP() {
		t.Error("HasDHCP() on nil receiver should return false")
	}
}

func TestCommonDevice_HasRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		device common.CommonDevice
		want   bool
	}{
		{
			name:   "empty routes returns false",
			device: common.CommonDevice{},
			want:   false,
		},
		{
			name: "populated static routes returns true",
			device: common.CommonDevice{
				Routing: common.Routing{
					StaticRoutes: []common.StaticRoute{{Network: "10.0.0.0/8"}},
				},
			},
			want: true,
		},
		{
			name: "gateways only returns true",
			device: common.CommonDevice{
				Routing: common.Routing{
					Gateways: []common.Gateway{{Name: "gw1"}},
				},
			},
			want: true,
		},
		{
			name: "gateway groups only returns true",
			device: common.CommonDevice{
				Routing: common.Routing{
					GatewayGroups: []common.GatewayGroup{{Name: "group1"}},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.device.HasRoutes(); got != tt.want {
				t.Errorf("HasRoutes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommonDevice_HasRoutes_NilReceiver(t *testing.T) {
	t.Parallel()

	var device *common.CommonDevice
	if device.HasRoutes() {
		t.Error("HasRoutes() on nil receiver should return false")
	}
}

func TestCommonDevice_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	device := common.CommonDevice{
		DeviceType: common.DeviceTypeOPNsense,
		Version:    "24.7",
		System: common.System{
			Hostname: "fw01",
			Domain:   "example.com",
			Timezone: "America/New_York",
			SSH:      common.SSH{Group: "admins"},
		},
		Interfaces: []common.Interface{
			{Name: "lan", PhysicalIf: "igb0", Enabled: true, IPAddress: "10.0.0.1", Subnet: "24"},
			{Name: "wan", PhysicalIf: "igb1", Enabled: true, Type: "dhcp"},
		},
		FirewallRules: []common.FirewallRule{
			{
				UUID:       "abc-123",
				Type:       common.RuleTypePass,
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{
					Address: "10.0.0.0/24",
					Port:    "443",
				},
				Protocol: "tcp",
				Log:      true,
			},
		},
		Users: []common.User{
			{Name: "root", UID: "0", Scope: "system"},
		},
		Groups: []common.Group{
			{Name: "admins", GID: "1999", Scope: "system"},
		},
		Sysctl: []common.SysctlItem{
			{Tunable: "net.inet.ip.forwarding", Value: "1"},
		},
	}

	data, err := json.Marshal(device)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var got common.CommonDevice
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Verify key fields survived round-trip.
	if got.DeviceType != device.DeviceType {
		t.Errorf("DeviceType = %q, want %q", got.DeviceType, device.DeviceType)
	}
	if got.System.Hostname != "fw01" {
		t.Errorf("System.Hostname = %q, want %q", got.System.Hostname, "fw01")
	}
	if len(got.Interfaces) != 2 {
		t.Errorf("Interfaces len = %d, want 2", len(got.Interfaces))
	}
	if len(got.FirewallRules) != 1 {
		t.Errorf("FirewallRules len = %d, want 1", len(got.FirewallRules))
	}
	if got.FirewallRules[0].Destination.Port != "443" {
		t.Errorf("FirewallRules[0].Destination.Port = %q, want %q", got.FirewallRules[0].Destination.Port, "443")
	}
	if len(got.Users) != 1 {
		t.Errorf("Users len = %d, want 1", len(got.Users))
	}
	if len(got.Sysctl) != 1 {
		t.Errorf("Sysctl len = %d, want 1", len(got.Sysctl))
	}
}

func TestCommonDevice_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	device := common.CommonDevice{
		DeviceType: common.DeviceTypeOPNsense,
		Version:    "24.7",
		System: common.System{
			Hostname: "fw01",
			Domain:   "example.com",
		},
		VPN: common.VPN{
			OpenVPN: common.OpenVPNConfig{
				Servers: []common.OpenVPNServer{
					{VPNID: "1", Mode: "server_tls", Protocol: "UDP4", LocalPort: "1194"},
				},
			},
			WireGuard: common.WireGuardConfig{
				Enabled: true,
				Servers: []common.WireGuardServer{
					{UUID: "wg1", Enabled: true, Port: "51820"},
				},
			},
		},
		Routing: common.Routing{
			Gateways: []common.Gateway{
				{Name: "WAN_GW", Interface: "wan", Address: "192.168.1.1"},
			},
			GatewayGroups: []common.GatewayGroup{
				{Name: "GWGROUP1", Items: []string{"WAN_GW|1"}, Trigger: "down"},
			},
		},
	}

	data, err := yaml.Marshal(device)
	if err != nil {
		t.Fatalf("yaml.Marshal failed: %v", err)
	}

	var got common.CommonDevice
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v", err)
	}

	if got.DeviceType != device.DeviceType {
		t.Errorf("DeviceType = %q, want %q", got.DeviceType, device.DeviceType)
	}
	if got.System.Hostname != "fw01" {
		t.Errorf("System.Hostname = %q, want %q", got.System.Hostname, "fw01")
	}
	if len(got.VPN.OpenVPN.Servers) != 1 {
		t.Errorf("OpenVPN.Servers len = %d, want 1", len(got.VPN.OpenVPN.Servers))
	}
	if got.VPN.WireGuard.Enabled != true {
		t.Errorf("WireGuard.Enabled = %v, want true", got.VPN.WireGuard.Enabled)
	}
	if len(got.Routing.Gateways) != 1 {
		t.Errorf("Routing.Gateways len = %d, want 1", len(got.Routing.Gateways))
	}
	if len(got.Routing.GatewayGroups) != 1 {
		t.Errorf("Routing.GatewayGroups len = %d, want 1", len(got.Routing.GatewayGroups))
	}
}

func TestCommonDevice_JSONOmitsZeroFields(t *testing.T) {
	t.Parallel()

	device := common.CommonDevice{
		DeviceType: common.DeviceTypeOPNsense,
	}

	data, err := json.Marshal(device)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	// Unmarshal into a generic map to inspect which keys are present.
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal to map failed: %v", err)
	}

	// Slices with omitempty should be absent.
	for _, key := range []string{"interfaces", "firewallRules", "users", "groups", "vlans", "sysctl"} {
		if _, present := m[key]; present {
			t.Errorf("expected %q to be omitted from JSON for zero-value device, but it was present", key)
		}
	}

	// Required struct fields (no omitempty on JSON tag) should be present.
	for _, key := range []string{"device_type", "system"} {
		if _, present := m[key]; !present {
			t.Errorf("expected %q to be present in JSON for zero-value device, but it was absent", key)
		}
	}
}

func TestCommonDevice_EnrichmentFieldsOptional(t *testing.T) {
	t.Parallel()

	device := common.CommonDevice{
		DeviceType: common.DeviceTypeOPNsense,
		Statistics: &common.Statistics{
			TotalInterfaces:    3,
			TotalFirewallRules: 10,
		},
		SecurityAssessment: &common.SecurityAssessment{
			OverallScore: 75,
		},
	}

	data, err := json.Marshal(device)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var got common.CommonDevice
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if got.Statistics == nil {
		t.Fatal("Statistics should not be nil after round-trip")
	}
	if got.Statistics.TotalInterfaces != 3 {
		t.Errorf("Statistics.TotalInterfaces = %d, want 3", got.Statistics.TotalInterfaces)
	}
	if got.SecurityAssessment == nil {
		t.Fatal("SecurityAssessment should not be nil after round-trip")
	}
	if got.SecurityAssessment.OverallScore != 75 {
		t.Errorf("SecurityAssessment.OverallScore = %d, want 75", got.SecurityAssessment.OverallScore)
	}

	// Analysis, PerformanceMetrics, ComplianceResults should remain nil.
	if got.Analysis != nil {
		t.Error("Analysis should be nil when not set")
	}
	if got.PerformanceMetrics != nil {
		t.Error("PerformanceMetrics should be nil when not set")
	}
	if got.ComplianceResults != nil {
		t.Error("ComplianceResults should be nil when not set")
	}
}

func TestParseDeviceType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  common.DeviceType
	}{
		{"empty string returns unknown", "", common.DeviceTypeUnknown},
		{"opnsense lowercase", "opnsense", common.DeviceTypeOPNsense},
		{"OPNsense mixed case", "OPNsense", common.DeviceTypeOPNsense},
		{"OPNsense with whitespace", " OPNsense ", common.DeviceTypeOPNsense},
		{"pfsense lowercase", "pfsense", common.DeviceTypePfSense},
		{"PfSense mixed case", "PfSense", common.DeviceTypePfSense},
		{"unknown string returns unknown", "unknown", common.DeviceTypeUnknown},
		{"routeros returns unknown", "routeros", common.DeviceTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := common.ParseDeviceType(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
