package builder_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
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

	// Verify key content is present (map iteration order may vary)
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

func TestMarkdownBuilder_BuildVLANTable_Empty(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	tableSet := b.BuildVLANTable(nil)

	if len(tableSet.Rows) != 1 {
		t.Fatalf("Expected 1 row for empty VLAN, got %d", len(tableSet.Rows))
	}

	// Verify "No VLANs configured" message
	found := false
	for _, cell := range tableSet.Rows[0] {
		if strings.Contains(cell, "No VLANs configured") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'No VLANs configured' message in empty VLAN table")
	}
}

func TestMarkdownBuilder_BuildVLANTable_SingleVLAN(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	vlans := []model.VLAN{
		{
			Vlanif:  "vlan10",
			If:      "em0",
			Tag:     "10",
			Descr:   "Management VLAN",
			Created: "2024-01-01",
			Updated: "2024-01-02",
		},
	}
	tableSet := b.BuildVLANTable(vlans)

	if len(tableSet.Rows) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(tableSet.Rows))
	}

	row := tableSet.Rows[0]
	if row[0] != "vlan10" {
		t.Errorf("Expected VLAN interface 'vlan10', got '%s'", row[0])
	}
	if row[1] != "em0" {
		t.Errorf("Expected physical interface 'em0', got '%s'", row[1])
	}
	if row[2] != "10" {
		t.Errorf("Expected VLAN tag '10', got '%s'", row[2])
	}
	if row[3] != "Management VLAN" {
		t.Errorf("Expected description 'Management VLAN', got '%s'", row[3])
	}
}

func TestMarkdownBuilder_BuildVLANTable_MultipleVLANs(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	vlans := []model.VLAN{
		{Vlanif: "vlan10", If: "em0", Tag: "10", Descr: "Management"},
		{Vlanif: "vlan20", If: "em0", Tag: "20", Descr: "DMZ"},
		{Vlanif: "vlan30", If: "em1", Tag: "30", Descr: "Guest"},
	}
	tableSet := b.BuildVLANTable(vlans)

	if len(tableSet.Rows) != 3 {
		t.Fatalf("Expected 3 rows, got %d", len(tableSet.Rows))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Static Routes Table Tests (Issue #67)
// ─────────────────────────────────────────────────────────────────────────────

func TestMarkdownBuilder_BuildStaticRoutesTable_Empty(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	tableSet := b.BuildStaticRoutesTable(nil)

	if len(tableSet.Rows) != 1 {
		t.Fatalf("Expected 1 row for empty routes, got %d", len(tableSet.Rows))
	}

	found := false
	for _, cell := range tableSet.Rows[0] {
		if strings.Contains(cell, "No static routes configured") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'No static routes configured' message")
	}
}

func TestMarkdownBuilder_BuildStaticRoutesTable_WithRoutes(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	routes := []model.StaticRoute{
		{
			Network:  "10.0.0.0/8",
			Gateway:  "192.168.1.1",
			Descr:    "Internal networks",
			Disabled: false,
			Created:  "2024-01-01",
			Updated:  "2024-01-02",
		},
		{
			Network:  "172.16.0.0/12",
			Gateway:  "192.168.1.2",
			Descr:    "VPN networks",
			Disabled: true,
			Created:  "2024-01-01",
			Updated:  "2024-01-02",
		},
	}
	tableSet := b.BuildStaticRoutesTable(routes)

	if len(tableSet.Rows) != 2 {
		t.Fatalf("Expected 2 rows, got %d", len(tableSet.Rows))
	}

	// First route should be enabled
	if !strings.Contains(tableSet.Rows[0][3], "Enabled") {
		t.Errorf("Expected first route to be Enabled, got '%s'", tableSet.Rows[0][3])
	}

	// Second route should be disabled
	if tableSet.Rows[1][3] != "Disabled" {
		t.Errorf("Expected second route to be Disabled, got '%s'", tableSet.Rows[1][3])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IPsec Section Tests (Issue #67)
// ─────────────────────────────────────────────────────────────────────────────

func TestMarkdownBuilder_BuildIPsecSection_Nil(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocument()
	// OPNsense.IPsec is nil by default

	output := b.BuildIPsecSection(data)

	if !strings.Contains(output, "### IPsec VPN Configuration") {
		t.Error("Expected IPsec section header")
	}
	if !strings.Contains(output, "No IPsec configuration present") {
		t.Error("Expected 'No IPsec configuration present' message for nil IPsec")
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
		"#### Charon IKE Daemon Configuration",
		"**Threads**",
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
		"#### Client-Specific Overrides",
		"No client-specific overrides configured",
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

func TestMarkdownBuilder_BuildOpenVPNSection_WithCSC(t *testing.T) {
	t.Parallel()

	b := builder.NewMarkdownBuilder()
	data := createTestDocumentWithOpenVPNCSC()

	output := b.BuildOpenVPNSection(data)

	expectedContent := []string{
		"#### Client-Specific Overrides",
		"client1",
		"10.8.0.10/32",
		"192.168.10.0/24",
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
// Test Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

// createTestDocument creates a minimal test document for testing.
func createTestDocument() *model.OpnSenseDocument {
	return &model.OpnSenseDocument{
		Version: "1.0",
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "example.com",
			User:     []model.User{{Name: "admin", Scope: "system"}},
			Group:    []model.Group{{Name: "admins", Scope: "system"}},
			Firmware: model.Firmware{Version: "24.1"},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"lan": {If: "em0", Enable: "1", IPAddr: "192.168.1.1", Subnet: "24"},
				"wan": {If: "em1", Enable: "1"},
			},
		},
		Dhcpd: model.Dhcpd{
			Items: map[string]model.DhcpdInterface{
				"lan": {Enable: "1", Range: model.Range{From: "192.168.1.100", To: "192.168.1.200"}},
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{Type: "pass", Interface: []string{"lan"}, Protocol: "tcp", Descr: "Allow LAN"},
			},
		},
		Nat: model.Nat{
			Outbound: model.Outbound{Mode: "automatic"},
		},
	}
}

// createTestDocumentWithIPsec creates a test document with IPsec configuration.
func createTestDocumentWithIPsec() *model.OpnSenseDocument {
	doc := createTestDocument()
	ipsec := &model.IPsec{}
	ipsec.General.Enabled = "1"
	ipsec.General.PreferredOldsa = "0"
	ipsec.General.Disablevpnrules = "0"
	ipsec.Charon.Threads = "16"
	ipsec.Charon.IkesaTableSize = "1"
	ipsec.Charon.MaxIkev1Exchanges = "3"
	ipsec.Charon.RetransmitTries = "5"
	ipsec.Charon.RetransmitTimeout = "4.0"
	ipsec.Charon.MakeBeforeBreak = "0"
	doc.OPNsense.IPsec = ipsec
	return doc
}

// createTestDocumentWithOpenVPN creates a test document with OpenVPN servers.
func createTestDocumentWithOpenVPN() *model.OpnSenseDocument {
	doc := createTestDocument()
	doc.OpenVPN.Servers = []model.OpenVPNServer{
		{
			Description:    "Site-to-Site VPN",
			Mode:           "p2p_tls",
			Protocol:       "UDP",
			Interface:      "wan",
			Local_port:     "1194",
			Tunnel_network: "10.8.0.0/24",
			Remote_network: "192.168.100.0/24",
			Cert_ref:       "cert123",
		},
	}
	return doc
}

// createTestDocumentWithOpenVPNClient creates a test document with OpenVPN clients.
func createTestDocumentWithOpenVPNClient() *model.OpnSenseDocument {
	doc := createTestDocument()
	doc.OpenVPN.Clients = []model.OpenVPNClient{
		{
			Description: "Remote Office",
			Server_addr: "vpn.example.com",
			Server_port: "1194",
			Mode:        "p2p_tls",
			Protocol:    "UDP",
			Cert_ref:    "cert456",
		},
	}
	return doc
}

// createTestDocumentWithOpenVPNCSC creates a test document with OpenVPN client-specific configs.
func createTestDocumentWithOpenVPNCSC() *model.OpnSenseDocument {
	doc := createTestDocument()
	doc.OpenVPN.CSC = []model.OpenVPNCSC{
		{
			Common_name:    "client1",
			Tunnel_network: "10.8.0.10/32",
			Local_network:  "192.168.10.0/24",
			Remote_network: "192.168.1.0/24",
			DNS_domain:     "client1.local",
		},
	}
	return doc
}

// createTestDocumentWithHA creates a test document with HA configuration.
func createTestDocumentWithHA() *model.OpnSenseDocument {
	doc := createTestDocument()
	doc.VirtualIP.Vip = "192.168.1.100"
	doc.HighAvailabilitySync = model.HighAvailabilitySync{
		Pfsyncinterface: "em2",
		Pfsyncpeerip:    "192.168.100.2",
		Synchronizetoip: "192.168.100.2",
		Username:        "admin",
		Disablepreempt:  "0",
		Pfsyncversion:   "1401",
	}
	return doc
}

// createTestDocumentWithAllFeatures creates a test document with all new features.
func createTestDocumentWithAllFeatures() *model.OpnSenseDocument {
	doc := createTestDocumentWithIPsec()
	doc.OpenVPN.Servers = []model.OpenVPNServer{
		{Description: "Test VPN", Mode: "p2p_tls", Protocol: "UDP", Interface: "wan", Local_port: "1194"},
	}
	doc.VLANs.VLAN = []model.VLAN{
		{Vlanif: "vlan10", If: "em0", Tag: "10", Descr: "Test VLAN"},
	}
	doc.StaticRoutes.Route = []model.StaticRoute{
		{Network: "10.0.0.0/8", Gateway: "192.168.1.1", Descr: "Test Route"},
	}
	doc.VirtualIP.Vip = "192.168.1.100"
	doc.HighAvailabilitySync = model.HighAvailabilitySync{
		Pfsyncinterface: "em2",
		Pfsyncpeerip:    "192.168.100.2",
	}
	return doc
}
