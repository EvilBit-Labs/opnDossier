package audit

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// TestModeController_GenerateBlueReport_WithPlugins tests blue report generation with plugin execution.
func TestModeController_GenerateBlueReport_WithPlugins(t *testing.T) {
	t.Parallel()

	registry := NewPluginRegistry()
	logger := newTestLogger(t)
	controller := NewModeController(registry, logger)

	// Register a mock plugin that succeeds
	mockPlugin := &mockCompliancePlugin{
		name:        "test-plugin",
		description: "Test plugin for blue report",
		version:     "1.0.0",
	}

	err := registry.RegisterPlugin(mockPlugin)
	if err != nil {
		t.Fatalf("Failed to register mock plugin: %v", err)
	}

	testConfig := &common.CommonDevice{
		System: common.System{
			Hostname: "test-host",
			Domain:   "test.local",
		},
	}

	tests := []struct {
		name            string
		selectedPlugins []string
		expectError     bool
	}{
		{
			name:            "with valid plugins",
			selectedPlugins: []string{"test-plugin"},
			expectError:     false,
		},
		{
			name:            "with invalid plugins",
			selectedPlugins: []string{"nonexistent-plugin"},
			expectError:     true, // Should error for non-existent plugin
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := &ModeConfig{
				Mode:            ModeBlue,
				SelectedPlugins: tt.selectedPlugins,
				Comprehensive:   true,
			}

			report, err := controller.GenerateReport(context.Background(), testConfig, config)
			if (err != nil) != tt.expectError {
				t.Errorf("GenerateReport() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError {
				if report == nil {
					t.Error("GenerateReport() returned nil report")
					return
				}

				// Verify metadata contains blue team specific fields
				if reportType, exists := report.Metadata["report_type"]; !exists || reportType != "blue_team" {
					t.Error("GenerateReport() missing or incorrect report_type in metadata")
				}

				// Check compliance check status
				if status, exists := report.Metadata["compliance_check_status"]; !exists {
					t.Error("GenerateReport() missing compliance_check_status in metadata")
				} else if status != "completed" {
					t.Errorf(
						"GenerateReport() compliance_check_status = %v, want 'completed' for valid plugin",
						status,
					)
				}
			}
		})
	}
}

// TestReport_AddAnalysisMethods_WithVariousConfigurations tests the analysis methods with different configurations.
func TestReport_AddAnalysisMethods_WithVariousConfigurations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *common.CommonDevice
	}{
		{
			name: "with full configuration",
			config: &common.CommonDevice{
				System: common.System{
					Hostname: "test-firewall",
					Domain:   "example.com",
				},
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true, PhysicalIf: "em0"},
					{Name: "wan", Enabled: true, PhysicalIf: "em1"},
				},
				FirewallRules: []common.FirewallRule{
					{
						Type:        "pass",
						Protocol:    "tcp",
						Description: "Allow HTTP",
					},
				},
				NAT: common.NATConfig{
					OutboundMode: "automatic",
				},
				DHCP: []common.DHCPScope{
					{
						Interface: "lan",
						Enabled:   true,
						Range: common.DHCPRange{
							From: "192.168.1.100",
							To:   "192.168.1.200",
						},
					},
				},
				Certificates: []common.Certificate{
					{
						Description: "Test Certificate",
						Certificate: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
					},
				},
				VPN: common.VPN{
					OpenVPN: common.OpenVPNConfig{
						Servers: []common.OpenVPNServer{
							{
								Mode:      "server_tls",
								Protocol:  "udp",
								LocalPort: "1194",
							},
						},
						Clients: []common.OpenVPNClient{
							{
								Description: "Test VPN Client",
							},
						},
					},
				},
				Routing: common.Routing{
					StaticRoutes: []common.StaticRoute{
						{
							Network:     "10.0.0.0/24",
							Gateway:     "192.168.1.1",
							Description: "Test Route",
						},
					},
				},
				HighAvailability: common.HighAvailability{
					SynchronizeToIP: "192.168.2.100",
					PfsyncInterface: "lan",
				},
			},
		},
		{
			name: "with minimal configuration",
			config: &common.CommonDevice{
				System: common.System{
					Hostname: "",
					Domain:   "",
				},
			},
		},
		{
			name:   "with nil configuration",
			config: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report := &Report{
				Configuration: tt.config,
				Metadata:      make(map[string]any),
			}

			// Test all analysis methods
			report.addSystemMetadata()
			report.addInterfaceAnalysis()
			report.addFirewallRuleAnalysis()
			report.addNATAnalysis()
			report.addDHCPAnalysis()
			report.addCertificateAnalysis()
			report.addVPNAnalysis()
			report.addStaticRouteAnalysis()
			report.addHighAvailabilityAnalysis()

			// Verify metadata was populated
			if len(report.Metadata) == 0 {
				t.Error("Analysis methods should populate metadata")
			}

			// Check specific fields for full configuration
			if tt.name == "with full configuration" {
				if hostname, exists := report.Metadata["system_hostname"]; !exists || hostname != "test-firewall" {
					t.Error("addSystemMetadata() should set system_hostname")
				}

				if domain, exists := report.Metadata["system_domain"]; !exists || domain != "example.com" {
					t.Error("addSystemMetadata() should set system_domain")
				}

				if interfaceCount, exists := report.Metadata["interface_count"]; !exists || interfaceCount != 2 {
					t.Errorf("addInterfaceAnalysis() interface_count = %v, want 2", interfaceCount)
				}

				if ruleCount, exists := report.Metadata["firewall_rule_count"]; !exists || ruleCount != 1 {
					t.Errorf("addFirewallRuleAnalysis() firewall_rule_count = %v, want 1", ruleCount)
				}

				if natMode, exists := report.Metadata["nat_mode"]; !exists || natMode != "automatic" {
					t.Errorf("addNATAnalysis() nat_mode = %v, want 'automatic'", natMode)
				}

				if dhcpEnabled, exists := report.Metadata["dhcp_enabled"]; !exists || dhcpEnabled != true {
					t.Errorf("addDHCPAnalysis() dhcp_enabled = %v, want true", dhcpEnabled)
				}

				if certsConfigured, exists := report.Metadata["certificates_configured"]; !exists ||
					certsConfigured != true {
					t.Errorf("addCertificateAnalysis() certificates_configured = %v, want true", certsConfigured)
				}

				if openvpnConfigured, exists := report.Metadata["openvpn_configured"]; !exists ||
					openvpnConfigured != true {
					t.Errorf("addVPNAnalysis() openvpn_configured = %v, want true", openvpnConfigured)
				}

				if serverCount, exists := report.Metadata["openvpn_server_count"]; !exists || serverCount != 1 {
					t.Errorf("addVPNAnalysis() openvpn_server_count = %v, want 1", serverCount)
				}

				if clientCount, exists := report.Metadata["openvpn_client_count"]; !exists || clientCount != 1 {
					t.Errorf("addVPNAnalysis() openvpn_client_count = %v, want 1", clientCount)
				}

				if routeCount, exists := report.Metadata["static_route_count"]; !exists || routeCount != 1 {
					t.Errorf("addStaticRouteAnalysis() static_route_count = %v, want 1", routeCount)
				}

				if haEnabled, exists := report.Metadata["ha_enabled"]; !exists || haEnabled != true {
					t.Errorf("addHighAvailabilityAnalysis() ha_enabled = %v, want true", haEnabled)
				}

				if haSyncIP, exists := report.Metadata["ha_sync_ip"]; !exists || haSyncIP != "192.168.2.100" {
					t.Errorf("addHighAvailabilityAnalysis() ha_sync_ip = %v, want '192.168.2.100'", haSyncIP)
				}

				if haPfsyncInterface, exists := report.Metadata["ha_pfsync_interface"]; !exists ||
					haPfsyncInterface != "lan" {
					t.Errorf("addHighAvailabilityAnalysis() ha_pfsync_interface = %v, want 'lan'", haPfsyncInterface)
				}
			}

			// Check fields for minimal configuration
			if tt.name == "with minimal configuration" {
				// Should not have hostname/domain if empty
				if hostname, exists := report.Metadata["system_hostname"]; exists && hostname != "" {
					t.Error("addSystemMetadata() should not set empty hostname")
				}

				if domain, exists := report.Metadata["system_domain"]; exists && domain != "" {
					t.Error("addSystemMetadata() should not set empty domain")
				}

				if dhcpEnabled, exists := report.Metadata["dhcp_enabled"]; !exists || dhcpEnabled != false {
					t.Errorf("addDHCPAnalysis() dhcp_enabled = %v, want false for no DHCP config", dhcpEnabled)
				}

				if certsConfigured, exists := report.Metadata["certificates_configured"]; !exists ||
					certsConfigured != false {
					t.Errorf(
						"addCertificateAnalysis() certificates_configured = %v, want false for no certs",
						certsConfigured,
					)
				}

				if haEnabled, exists := report.Metadata["ha_enabled"]; !exists || haEnabled != false {
					t.Errorf("addHighAvailabilityAnalysis() ha_enabled = %v, want false for no HA config", haEnabled)
				}
			}
		})
	}
}

// TestReport_DHCPAnalysis_EdgeCases tests DHCP analysis with edge cases.
func TestReport_DHCPAnalysis_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		config          *common.CommonDevice
		expectedEnabled bool
	}{
		{
			name: "DHCP disabled explicitly",
			config: &common.CommonDevice{
				DHCP: []common.DHCPScope{
					{Interface: "lan", Enabled: false},
				},
			},
			expectedEnabled: false,
		},
		{
			name: "DHCP enabled",
			config: &common.CommonDevice{
				DHCP: []common.DHCPScope{
					{Interface: "lan", Enabled: true},
				},
			},
			expectedEnabled: true,
		},
		{
			name: "no LAN DHCP config",
			config: &common.CommonDevice{
				DHCP: []common.DHCPScope{
					{Interface: "wan", Enabled: true},
				},
			},
			expectedEnabled: false,
		},
		{
			name: "empty DHCP config",
			config: &common.CommonDevice{
				DHCP: []common.DHCPScope{},
			},
			expectedEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report := &Report{
				Configuration: tt.config,
				Metadata:      make(map[string]any),
			}

			report.addDHCPAnalysis()

			dhcpEnabled, exists := report.Metadata["dhcp_enabled"]
			if !exists {
				t.Error("addDHCPAnalysis() should set dhcp_enabled")
			}

			if dhcpEnabled != tt.expectedEnabled {
				t.Errorf("addDHCPAnalysis() dhcp_enabled = %v, want %v", dhcpEnabled, tt.expectedEnabled)
			}

			// Should always have analysis completed flag
			if completed, exists := report.Metadata["dhcp_analysis_completed"]; !exists || completed != true {
				t.Error("addDHCPAnalysis() should set dhcp_analysis_completed")
			}
		})
	}
}

// TestReport_CertificateAnalysis_EdgeCases tests certificate analysis edge cases.
func TestReport_CertificateAnalysis_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		config             *common.CommonDevice
		expectedConfigured bool
	}{
		{
			name: "certificate with content",
			config: &common.CommonDevice{
				Certificates: []common.Certificate{
					{Certificate: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"},
				},
			},
			expectedConfigured: true,
		},
		{
			name: "no certificates",
			config: &common.CommonDevice{
				Certificates: []common.Certificate{},
			},
			expectedConfigured: false,
		},
		{
			name:               "nil certificates",
			config:             &common.CommonDevice{},
			expectedConfigured: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report := &Report{
				Configuration: tt.config,
				Metadata:      make(map[string]any),
			}

			report.addCertificateAnalysis()

			certsConfigured, exists := report.Metadata["certificates_configured"]
			if !exists {
				t.Error("addCertificateAnalysis() should set certificates_configured")
			}

			if certsConfigured != tt.expectedConfigured {
				t.Errorf(
					"addCertificateAnalysis() certificates_configured = %v, want %v",
					certsConfigured,
					tt.expectedConfigured,
				)
			}
		})
	}
}

// TestReport_HighAvailabilityAnalysis_EdgeCases tests HA analysis with various configurations.
func TestReport_HighAvailabilityAnalysis_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     *common.CommonDevice
		expectedHA bool
		expectedIP string
		expectedIF string
	}{
		{
			name: "HA with sync IP only",
			config: &common.CommonDevice{
				HighAvailability: common.HighAvailability{
					SynchronizeToIP: "192.168.1.100",
					PfsyncInterface: "",
				},
			},
			expectedHA: true,
			expectedIP: "192.168.1.100",
			expectedIF: "",
		},
		{
			name: "HA with pfsync interface only",
			config: &common.CommonDevice{
				HighAvailability: common.HighAvailability{
					SynchronizeToIP: "",
					PfsyncInterface: "lan",
				},
			},
			expectedHA: true,
			expectedIP: "",
			expectedIF: "lan",
		},
		{
			name: "HA with both sync IP and interface",
			config: &common.CommonDevice{
				HighAvailability: common.HighAvailability{
					SynchronizeToIP: "192.168.1.100",
					PfsyncInterface: "lan",
				},
			},
			expectedHA: true,
			expectedIP: "192.168.1.100",
			expectedIF: "lan",
		},
		{
			name: "HA disabled (empty values)",
			config: &common.CommonDevice{
				HighAvailability: common.HighAvailability{
					SynchronizeToIP: "",
					PfsyncInterface: "",
				},
			},
			expectedHA: false,
			expectedIP: "",
			expectedIF: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report := &Report{
				Configuration: tt.config,
				Metadata:      make(map[string]any),
			}

			report.addHighAvailabilityAnalysis()

			haEnabled, exists := report.Metadata["ha_enabled"]
			if !exists {
				t.Error("addHighAvailabilityAnalysis() should set ha_enabled")
			}

			if haEnabled != tt.expectedHA {
				t.Errorf("addHighAvailabilityAnalysis() ha_enabled = %v, want %v", haEnabled, tt.expectedHA)
			}

			if tt.expectedHA {
				// Check sync IP
				haSyncIP, exists := report.Metadata["ha_sync_ip"]
				if !exists {
					t.Error("addHighAvailabilityAnalysis() should set ha_sync_ip when HA is enabled")
				}
				if haSyncIP != tt.expectedIP {
					t.Errorf("addHighAvailabilityAnalysis() ha_sync_ip = %v, want %v", haSyncIP, tt.expectedIP)
				}

				// Check pfsync interface
				haPfsyncIF, exists := report.Metadata["ha_pfsync_interface"]
				if !exists {
					t.Error("addHighAvailabilityAnalysis() should set ha_pfsync_interface when HA is enabled")
				}
				if haPfsyncIF != tt.expectedIF {
					t.Errorf(
						"addHighAvailabilityAnalysis() ha_pfsync_interface = %v, want %v",
						haPfsyncIF,
						tt.expectedIF,
					)
				}
			}
		})
	}
}

// TestReport_InterfaceAnalysis_EdgeCases tests interface analysis with various interface configurations.
func TestReport_InterfaceAnalysis_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		config                 *common.CommonDevice
		expectedInterfaceCount int
	}{
		{
			name: "with multiple interfaces",
			config: &common.CommonDevice{
				Interfaces: []common.Interface{
					{Name: "lan", Enabled: true, PhysicalIf: "em0"},
					{Name: "wan", Enabled: true, PhysicalIf: "em1"},
					{Name: "opt1", Enabled: true, PhysicalIf: "em2"},
				},
			},
			expectedInterfaceCount: 3,
		},
		{
			name: "with no interfaces",
			config: &common.CommonDevice{
				Interfaces: []common.Interface{},
			},
			expectedInterfaceCount: 0,
		},
		{
			name: "with nil interfaces",
			config: &common.CommonDevice{
				Interfaces: nil,
			},
			expectedInterfaceCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report := &Report{
				Configuration: tt.config,
				Metadata:      make(map[string]any),
			}

			report.addInterfaceAnalysis()

			// Always should have analysis completed flag
			if completed, exists := report.Metadata["interface_analysis_completed"]; !exists || completed != true {
				t.Error("addInterfaceAnalysis() should set interface_analysis_completed")
			}

			interfaceCount, exists := report.Metadata["interface_count"]
			if !exists {
				t.Error("addInterfaceAnalysis() should set interface_count")
			}

			if interfaceCount != tt.expectedInterfaceCount {
				t.Errorf(
					"addInterfaceAnalysis() interface_count = %v, want %v",
					interfaceCount,
					tt.expectedInterfaceCount,
				)
			}
		})
	}
}
