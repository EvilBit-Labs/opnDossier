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
