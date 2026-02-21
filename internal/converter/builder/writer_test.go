package builder_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	internalMarkdown "github.com/EvilBit-Labs/opnDossier/internal/markdown"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/nao1215/markdown"
)

func TestMarkdownBuilder_WriteSystemSection(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocument()

	var buf bytes.Buffer
	err := b.WriteSystemSection(&buf, data)
	if err != nil {
		t.Fatalf("WriteSystemSection returned error: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("WriteSystemSection produced empty output")
	}

	// Verify it matches the Build method output
	expected := b.BuildSystemSection(data)
	if output != expected {
		t.Errorf("WriteSystemSection output differs from BuildSystemSection:\ngot:\n%s\nwant:\n%s", output, expected)
	}
}

func TestMarkdownBuilder_WriteNetworkSection(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocument()

	var buf bytes.Buffer
	err := b.WriteNetworkSection(&buf, data)
	if err != nil {
		t.Fatalf("WriteNetworkSection returned error: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("WriteNetworkSection produced empty output")
	}

	// Verify key content is present
	expectedContent := []string{
		"## Network Configuration",
		"### Interfaces",
		"lan",
		"wan",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("WriteNetworkSection missing expected content: %s", content)
		}
	}
}

func TestMarkdownBuilder_WriteSecuritySection(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocument()

	var buf bytes.Buffer
	err := b.WriteSecuritySection(&buf, data)
	if err != nil {
		t.Fatalf("WriteSecuritySection returned error: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("WriteSecuritySection produced empty output")
	}

	// Verify key content is present
	expectedContent := []string{
		"## Security Configuration",
		"### NAT Configuration",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("WriteSecuritySection missing expected content: %s", content)
		}
	}
}

func TestMarkdownBuilder_WriteServicesSection(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocument()

	var buf bytes.Buffer
	err := b.WriteServicesSection(&buf, data)
	if err != nil {
		t.Fatalf("WriteServicesSection returned error: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("WriteServicesSection produced empty output")
	}

	// Verify key content is present
	expectedContent := []string{
		"## Service Configuration",
		"### DHCP Server",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("WriteServicesSection missing expected content: %s", content)
		}
	}
}

func TestMarkdownBuilder_WriteStandardReport(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocument()

	var buf bytes.Buffer
	err := b.WriteStandardReport(&buf, data)
	if err != nil {
		t.Fatalf("WriteStandardReport returned error: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("WriteStandardReport produced empty output")
	}

	// Verify key sections are present
	expectedSections := []string{
		"# OPNsense Configuration Summary",
		"## System Information",
		"## Table of Contents",
		"## System Configuration",
		"## Network Configuration",
		"## Security Configuration",
		"## Service Configuration",
	}

	for _, section := range expectedSections {
		if !strings.Contains(output, section) {
			t.Errorf("WriteStandardReport missing expected section: %s", section)
		}
	}
}

func TestMarkdownBuilder_WriteComprehensiveReport(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocument()

	var buf bytes.Buffer
	err := b.WriteComprehensiveReport(&buf, data)
	if err != nil {
		t.Fatalf("WriteComprehensiveReport returned error: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("WriteComprehensiveReport produced empty output")
	}

	// Comprehensive report should include System Groups in TOC
	if !strings.Contains(output, "System Groups") {
		t.Error("WriteComprehensiveReport missing System Groups in table of contents")
	}
}

func TestMarkdownBuilder_WriteStandardReport_NilData(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()

	var buf bytes.Buffer
	err := b.WriteStandardReport(&buf, nil)

	if err == nil {
		t.Error("WriteStandardReport should return error for nil data")
	}
}

func TestMarkdownBuilder_WriteComprehensiveReport_NilData(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()

	var buf bytes.Buffer
	err := b.WriteComprehensiveReport(&buf, nil)

	if err == nil {
		t.Error("WriteComprehensiveReport should return error for nil data")
	}
}

func TestSectionWriter_Interface(t *testing.T) {
	t.Parallel()

	// Ensure MarkdownBuilder implements SectionWriter
	var _ builder.SectionWriter = (*builder.MarkdownBuilder)(nil)
}

// ─────────────────────────────────────────────────────────────────────────────
// VLAN Table Tests (Issue #67)
// ─────────────────────────────────────────────────────────────────────────────

func TestMarkdownBuilder_WriteVLANTable_Empty(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.WriteVLANTable(md, nil)
	output := md.String()

	// Verify "No VLANs configured" message
	if !strings.Contains(output, "No VLANs configured") {
		t.Error("Expected 'No VLANs configured' message in empty VLAN table")
	}
}

func TestMarkdownBuilder_WriteVLANTable_SingleVLAN(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	vlans := []common.VLAN{
		{
			VLANIf:      "vlan10",
			PhysicalIf:  "em0",
			Tag:         "10",
			Description: "Management VLAN",
			Created:     "2024-01-01",
			Updated:     "2024-01-02",
		},
	}
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.WriteVLANTable(md, vlans)
	output := md.String()

	if !strings.Contains(output, "vlan10") {
		t.Error("Expected VLAN interface 'vlan10' in output")
	}
	if !strings.Contains(output, "em0") {
		t.Error("Expected physical interface 'em0' in output")
	}
	if !strings.Contains(output, "10") {
		t.Error("Expected VLAN tag '10' in output")
	}
	if !strings.Contains(output, "Management VLAN") {
		t.Error("Expected description 'Management VLAN' in output")
	}
}

func TestMarkdownBuilder_WriteVLANTable_MultipleVLANs(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	vlans := []common.VLAN{
		{VLANIf: "vlan10", PhysicalIf: "em0", Tag: "10", Description: "Management"},
		{VLANIf: "vlan20", PhysicalIf: "em0", Tag: "20", Description: "DMZ"},
		{VLANIf: "vlan30", PhysicalIf: "em1", Tag: "30", Description: "Guest"},
	}
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.WriteVLANTable(md, vlans)
	output := md.String()

	// Verify all VLANs are present
	if !strings.Contains(output, "vlan10") || !strings.Contains(output, "vlan20") ||
		!strings.Contains(output, "vlan30") {
		t.Error("Expected all VLAN interfaces in output")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Static Routes Table Tests (Issue #67)
// ─────────────────────────────────────────────────────────────────────────────

func TestMarkdownBuilder_WriteStaticRoutesTable_Empty(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.WriteStaticRoutesTable(md, nil)
	output := md.String()

	if !strings.Contains(output, "No static routes configured") {
		t.Error("Expected 'No static routes configured' message")
	}
}

func TestMarkdownBuilder_WriteStaticRoutesTable_WithRoutes(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	routes := []common.StaticRoute{
		{
			Network:     "10.0.0.0/8",
			Gateway:     "192.168.1.1",
			Description: "Internal networks",
			Disabled:    false,
			Created:     "2024-01-01",
			Updated:     "2024-01-02",
		},
		{
			Network:     "172.16.0.0/12",
			Gateway:     "192.168.1.2",
			Description: "VPN networks",
			Disabled:    true,
			Created:     "2024-01-01",
			Updated:     "2024-01-02",
		},
	}
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.WriteStaticRoutesTable(md, routes)
	output := md.String()

	// Verify routes are present
	if !strings.Contains(output, "10.0.0.0/8") {
		t.Error("Expected first route network in output")
	}
	if !strings.Contains(output, "172.16.0.0/12") {
		t.Error("Expected second route network in output")
	}

	// First route should be enabled, second disabled
	if !strings.Contains(output, "Enabled") {
		t.Error("Expected 'Enabled' status in output")
	}
	if !strings.Contains(output, "Disabled") {
		t.Error("Expected 'Disabled' status in output")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IPsec Section Tests (Issue #67)
// ─────────────────────────────────────────────────────────────────────────────

func TestMarkdownBuilder_BuildIPsecSection_Nil(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocument()
	// VPN.IPsec.Enabled is false by default

	output := b.BuildIPsecSection(data)

	if !strings.Contains(output, "### IPsec VPN Configuration") {
		t.Error("Expected IPsec section header")
	}
	if !strings.Contains(output, "No IPsec configuration present") {
		t.Error("Expected 'No IPsec configuration present' message for disabled IPsec")
	}
}

func TestMarkdownBuilder_BuildIPsecSection_Configured(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocumentWithIPsec()

	output := b.BuildIPsecSection(data)

	expectedContent := []string{
		"### IPsec VPN Configuration",
		"#### General Configuration",
		"**Enabled**",
	}

	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("Expected IPsec section to contain '%s'", content)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// OpenVPN Section Tests (Issue #67)
// ─────────────────────────────────────────────────────────────────────────────

func TestMarkdownBuilder_BuildOpenVPNSection_Empty(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocument()

	output := b.BuildOpenVPNSection(data)

	expectedContent := []string{
		"### OpenVPN Configuration",
		"#### OpenVPN Servers",
		"No OpenVPN servers configured",
		"#### OpenVPN Clients",
		"No OpenVPN clients configured",
	}

	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("Expected OpenVPN section to contain '%s'", content)
		}
	}
}

func TestMarkdownBuilder_BuildOpenVPNSection_WithServers(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocumentWithOpenVPN()

	output := b.BuildOpenVPNSection(data)

	expectedContent := []string{
		"### OpenVPN Configuration",
		"#### OpenVPN Servers",
		"Site-to-Site VPN",
		"p2p_tls",
		"UDP",
		"wan",
		"1194",
		"10.8.0.0/24",
	}

	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("Expected OpenVPN section to contain '%s'", content)
		}
	}
}

func TestMarkdownBuilder_BuildOpenVPNSection_WithClients(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocumentWithOpenVPNClient()

	output := b.BuildOpenVPNSection(data)

	expectedContent := []string{
		"#### OpenVPN Clients",
		"Remote Office",
		"vpn.example.com",
		"1194",
	}

	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("Expected OpenVPN section to contain '%s'", content)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// High Availability Section Tests (Issue #67)
// ─────────────────────────────────────────────────────────────────────────────

func TestMarkdownBuilder_BuildHASection_Empty(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocument()

	output := b.BuildHASection(data)

	expectedContent := []string{
		"### High Availability & CARP",
		"#### Virtual IP Addresses (CARP)",
		"No virtual IPs configured",
		"#### HA Synchronization Settings",
		"No HA synchronization configured",
	}

	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("Expected HA section to contain '%s'", content)
		}
	}
}

func TestMarkdownBuilder_BuildHASection_Configured(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocumentWithHA()

	output := b.BuildHASection(data)

	expectedContent := []string{
		"### High Availability & CARP",
		"192.168.1.100",
		"CARP",
		"#### HA Synchronization Settings",
		"**pfSync Interface**",
		"em2",
		"**pfSync Peer IP**",
		"192.168.100.2",
	}

	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("Expected HA section to contain '%s'", content)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Comprehensive Report Tests (Issue #67)
// ─────────────────────────────────────────────────────────────────────────────

func TestMarkdownBuilder_WriteComprehensiveReport_NewSections(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocumentWithAllFeatures()

	var buf bytes.Buffer
	err := b.WriteComprehensiveReport(&buf, data)
	if err != nil {
		t.Fatalf("WriteComprehensiveReport returned error: %v", err)
	}

	output := buf.String()

	// Check Table of Contents includes new sections
	tocSections := []string{
		"[VLANs](#vlan-configuration)",
		"[Static Routes](#static-routes)",
		"[IPsec VPN](#ipsec-vpn-configuration)",
		"[OpenVPN](#openvpn-configuration)",
		"[High Availability](#high-availability--carp)",
	}

	for _, section := range tocSections {
		if !strings.Contains(output, section) {
			t.Errorf("Comprehensive report TOC missing: %s", section)
		}
	}

	// Check actual sections are present
	sections := []string{
		"### VLAN Configuration",
		"### Static Routes",
		"### IPsec VPN Configuration",
		"### OpenVPN Configuration",
		"### High Availability & CARP",
	}

	for _, section := range sections {
		if !strings.Contains(output, section) {
			t.Errorf("Comprehensive report missing section: %s", section)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Markdown Syntax Validation Tests (goldmark round-trip)
// ─────────────────────────────────────────────────────────────────────────────

// TestMarkdownBuilder_ValidateMarkdownSyntax validates that all generated markdown
// passes goldmark parsing.
func TestMarkdownBuilder_ValidateMarkdownSyntax(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocumentWithAllFeatures()

	tests := []struct {
		name     string
		generate func() string
	}{
		{
			name: "SystemSection",
			generate: func() string {
				return b.BuildSystemSection(data)
			},
		},
		{
			name: "NetworkSection",
			generate: func() string {
				return b.BuildNetworkSection(data)
			},
		},
		{
			name: "SecuritySection",
			generate: func() string {
				return b.BuildSecuritySection(data)
			},
		},
		{
			name: "ServicesSection",
			generate: func() string {
				return b.BuildServicesSection(data)
			},
		},
		{
			name: "IPsecSection",
			generate: func() string {
				return b.BuildIPsecSection(data)
			},
		},
		{
			name: "OpenVPNSection",
			generate: func() string {
				return b.BuildOpenVPNSection(data)
			},
		},
		{
			name: "HASection",
			generate: func() string {
				return b.BuildHASection(data)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			output := tt.generate()
			if output == "" {
				t.Fatalf("%s produced empty output", tt.name)
			}

			err := internalMarkdown.ValidateMarkdown(output)
			if err != nil {
				t.Errorf("%s produced invalid markdown: %v\nOutput:\n%s", tt.name, err, output)
			}
		})
	}
}

// TestMarkdownBuilder_ValidateStandardReport validates that the standard report
// produces valid markdown that passes goldmark parsing.
func TestMarkdownBuilder_ValidateStandardReport(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocumentWithAllFeatures()

	report, err := b.BuildStandardReport(data)
	if err != nil {
		t.Fatalf("BuildStandardReport returned error: %v", err)
	}

	if report == "" {
		t.Fatal("BuildStandardReport produced empty output")
	}

	err = internalMarkdown.ValidateMarkdown(report)
	if err != nil {
		t.Errorf("Standard report produced invalid markdown: %v", err)
	}
}

// TestMarkdownBuilder_ValidateComprehensiveReport validates that the comprehensive
// report produces valid markdown that passes goldmark parsing.
func TestMarkdownBuilder_ValidateComprehensiveReport(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocumentWithAllFeatures()

	report, err := b.BuildComprehensiveReport(data)
	if err != nil {
		t.Fatalf("BuildComprehensiveReport returned error: %v", err)
	}

	if report == "" {
		t.Fatal("BuildComprehensiveReport produced empty output")
	}

	err = internalMarkdown.ValidateMarkdown(report)
	if err != nil {
		t.Errorf("Comprehensive report produced invalid markdown: %v", err)
	}
}

// TestMarkdownBuilder_ValidateWriteMethods validates that the streaming Write*
// methods produce valid markdown that passes goldmark parsing.
func TestMarkdownBuilder_ValidateWriteMethods(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocumentWithAllFeatures()

	tests := []struct {
		name  string
		write func(buf *bytes.Buffer) error
	}{
		{
			name: "WriteSystemSection",
			write: func(buf *bytes.Buffer) error {
				return b.WriteSystemSection(buf, data)
			},
		},
		{
			name: "WriteNetworkSection",
			write: func(buf *bytes.Buffer) error {
				return b.WriteNetworkSection(buf, data)
			},
		},
		{
			name: "WriteSecuritySection",
			write: func(buf *bytes.Buffer) error {
				return b.WriteSecuritySection(buf, data)
			},
		},
		{
			name: "WriteServicesSection",
			write: func(buf *bytes.Buffer) error {
				return b.WriteServicesSection(buf, data)
			},
		},
		{
			name: "WriteStandardReport",
			write: func(buf *bytes.Buffer) error {
				return b.WriteStandardReport(buf, data)
			},
		},
		{
			name: "WriteComprehensiveReport",
			write: func(buf *bytes.Buffer) error {
				return b.WriteComprehensiveReport(buf, data)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			err := tt.write(&buf)
			if err != nil {
				t.Fatalf("%s returned error: %v", tt.name, err)
			}

			output := buf.String()
			if output == "" {
				t.Fatalf("%s produced empty output", tt.name)
			}

			err = internalMarkdown.ValidateMarkdown(output)
			if err != nil {
				t.Errorf("%s produced invalid markdown: %v", tt.name, err)
			}
		})
	}
}

// TestMarkdownBuilder_ValidateTableMethods validates that the Write*Table methods
// produce valid markdown tables that pass goldmark parsing.
func TestMarkdownBuilder_ValidateTableMethods(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocumentWithAllFeatures()

	tests := []struct {
		name  string
		write func(md *markdown.Markdown)
	}{
		{
			name: "WriteFirewallRulesTable",
			write: func(md *markdown.Markdown) {
				b.WriteFirewallRulesTable(md, data.FirewallRules)
			},
		},
		{
			name: "WriteInterfaceTable",
			write: func(md *markdown.Markdown) {
				b.WriteInterfaceTable(md, data.Interfaces)
			},
		},
		{
			name: "WriteUserTable",
			write: func(md *markdown.Markdown) {
				b.WriteUserTable(md, data.Users)
			},
		},
		{
			name: "WriteGroupTable",
			write: func(md *markdown.Markdown) {
				b.WriteGroupTable(md, data.Groups)
			},
		},
		{
			name: "WriteVLANTable",
			write: func(md *markdown.Markdown) {
				b.WriteVLANTable(md, data.VLANs)
			},
		},
		{
			name: "WriteStaticRoutesTable",
			write: func(md *markdown.Markdown) {
				b.WriteStaticRoutesTable(md, data.Routing.StaticRoutes)
			},
		},
		{
			name: "WriteOutboundNATTable_Empty",
			write: func(md *markdown.Markdown) {
				b.WriteOutboundNATTable(md, nil)
			},
		},
		{
			name: "WriteInboundNATTable_Empty",
			write: func(md *markdown.Markdown) {
				b.WriteInboundNATTable(md, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			md := markdown.NewMarkdown(&buf)
			tt.write(md)
			output := md.String()

			if output == "" {
				t.Fatalf("%s produced empty output", tt.name)
			}

			err := internalMarkdown.ValidateMarkdown(output)
			if err != nil {
				t.Errorf("%s produced invalid markdown: %v\nOutput:\n%s", tt.name, err, output)
			}
		})
	}
}

// TestMarkdownBuilder_ValidateEmptyData validates that the builder handles empty
// data gracefully and still produces valid markdown.
func TestMarkdownBuilder_ValidateEmptyData(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	// Minimal document with mostly empty fields
	data := &common.CommonDevice{
		Version: "1.0",
		System: common.System{
			Hostname: "empty-test",
			Domain:   "test.local",
			Firmware: common.Firmware{Version: "24.1"},
		},
	}

	tests := []struct {
		name     string
		generate func() string
	}{
		{
			name: "SystemSection_Empty",
			generate: func() string {
				return b.BuildSystemSection(data)
			},
		},
		{
			name: "NetworkSection_Empty",
			generate: func() string {
				return b.BuildNetworkSection(data)
			},
		},
		{
			name: "SecuritySection_Empty",
			generate: func() string {
				return b.BuildSecuritySection(data)
			},
		},
		{
			name: "ServicesSection_Empty",
			generate: func() string {
				return b.BuildServicesSection(data)
			},
		},
		{
			name: "IPsecSection_Empty",
			generate: func() string {
				return b.BuildIPsecSection(data)
			},
		},
		{
			name: "OpenVPNSection_Empty",
			generate: func() string {
				return b.BuildOpenVPNSection(data)
			},
		},
		{
			name: "HASection_Empty",
			generate: func() string {
				return b.BuildHASection(data)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			output := tt.generate()
			// Empty sections may produce minimal but valid markdown
			err := internalMarkdown.ValidateMarkdown(output)
			if err != nil {
				t.Errorf("%s produced invalid markdown: %v\nOutput:\n%s", tt.name, err, output)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

// createTestDocument creates a minimal test document for testing.
func createTestDocument() *common.CommonDevice {
	return &common.CommonDevice{
		Version: "1.0",
		System: common.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
			Firmware: common.Firmware{Version: "24.1"},
		},
		Users:  []common.User{{Name: "admin", Scope: "system"}},
		Groups: []common.Group{{Name: "admins", Scope: "system"}},
		Interfaces: []common.Interface{
			{Name: "lan", PhysicalIf: "em0", Enabled: true, IPAddress: "192.168.1.1", Subnet: "24"},
			{Name: "wan", PhysicalIf: "em1", Enabled: true},
		},
		DHCP: []common.DHCPScope{
			{Interface: "lan", Enabled: true, Range: common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"}},
		},
		FirewallRules: []common.FirewallRule{
			{Type: "pass", Interfaces: []string{"lan"}, Protocol: "tcp", Description: "Allow LAN"},
		},
		NAT: common.NATConfig{OutboundMode: "automatic"},
	}
}

// createTestDocumentWithIPsec creates a test document with IPsec configuration.
func createTestDocumentWithIPsec() *common.CommonDevice {
	doc := createTestDocument()
	doc.VPN.IPsec.Enabled = true
	return doc
}

// createTestDocumentWithOpenVPN creates a test document with OpenVPN servers.
func createTestDocumentWithOpenVPN() *common.CommonDevice {
	doc := createTestDocument()
	doc.VPN.OpenVPN.Servers = []common.OpenVPNServer{
		{
			Description:   "Site-to-Site VPN",
			Mode:          "p2p_tls",
			Protocol:      "UDP",
			Interface:     "wan",
			LocalPort:     "1194",
			TunnelNetwork: "10.8.0.0/24",
			RemoteNetwork: "192.168.100.0/24",
			CertRef:       "cert123",
		},
	}
	return doc
}

// createTestDocumentWithOpenVPNClient creates a test document with OpenVPN clients.
func createTestDocumentWithOpenVPNClient() *common.CommonDevice {
	doc := createTestDocument()
	doc.VPN.OpenVPN.Clients = []common.OpenVPNClient{
		{
			Description: "Remote Office",
			ServerAddr:  "vpn.example.com",
			ServerPort:  "1194",
			Mode:        "p2p_tls",
			Protocol:    "UDP",
			CertRef:     "cert456",
		},
	}
	return doc
}

// createTestDocumentWithHA creates a test document with HA configuration.
func createTestDocumentWithHA() *common.CommonDevice {
	doc := createTestDocument()
	doc.VirtualIPs = []common.VirtualIP{{Subnet: "192.168.1.100", Mode: "CARP"}}
	doc.HighAvailability = common.HighAvailability{
		PfsyncInterface: "em2",
		PfsyncPeerIP:    "192.168.100.2",
		SynchronizeToIP: "192.168.100.2",
		Username:        "admin",
		DisablePreempt:  false,
		PfsyncVersion:   "1401",
	}
	return doc
}

// createTestDocumentWithAllFeatures creates a test document with all new features.
func createTestDocumentWithAllFeatures() *common.CommonDevice {
	doc := createTestDocumentWithIPsec()
	doc.VPN.OpenVPN.Servers = []common.OpenVPNServer{
		{Description: "Test VPN", Mode: "p2p_tls", Protocol: "UDP", Interface: "wan", LocalPort: "1194"},
	}
	doc.VLANs = []common.VLAN{
		{VLANIf: "vlan10", PhysicalIf: "em0", Tag: "10", Description: "Test VLAN"},
	}
	doc.Routing.StaticRoutes = []common.StaticRoute{
		{Network: "10.0.0.0/8", Gateway: "192.168.1.1", Description: "Test Route"},
	}
	doc.VirtualIPs = []common.VirtualIP{{Subnet: "192.168.1.100", Mode: "CARP"}}
	doc.HighAvailability = common.HighAvailability{
		PfsyncInterface: "em2",
		PfsyncPeerIP:    "192.168.100.2",
	}
	return doc
}
