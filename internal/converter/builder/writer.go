// Package builder provides programmatic report building functionality for OPNsense configurations.
package builder

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/nao1215/markdown"
)

// SectionWriter defines the interface for streaming report generation.
// This interface enables memory-efficient output by writing sections directly
// to an io.Writer instead of accumulating strings in memory.
//
// Implementations should write each section immediately, allowing for:
// - Lower memory footprint for large configurations
// - Faster time-to-first-byte for output
// - Better support for piping to other tools.
type SectionWriter interface {
	// WriteSystemSection writes the system configuration section to the writer.
	WriteSystemSection(w io.Writer, data *model.OpnSenseDocument) error

	// WriteNetworkSection writes the network configuration section to the writer.
	WriteNetworkSection(w io.Writer, data *model.OpnSenseDocument) error

	// WriteSecuritySection writes the security configuration section to the writer.
	WriteSecuritySection(w io.Writer, data *model.OpnSenseDocument) error

	// WriteServicesSection writes the services configuration section to the writer.
	WriteServicesSection(w io.Writer, data *model.OpnSenseDocument) error

	// WriteStandardReport writes a complete standard report to the writer.
	WriteStandardReport(w io.Writer, data *model.OpnSenseDocument) error

	// WriteComprehensiveReport writes a complete comprehensive report to the writer.
	WriteComprehensiveReport(w io.Writer, data *model.OpnSenseDocument) error
}

// Ensure MarkdownBuilder implements SectionWriter.
var _ SectionWriter = (*MarkdownBuilder)(nil)

// WriteSystemSection writes the system configuration section directly to the writer.
func (b *MarkdownBuilder) WriteSystemSection(w io.Writer, data *model.OpnSenseDocument) error {
	section := b.BuildSystemSection(data)
	_, err := io.WriteString(w, section)
	return err
}

// WriteNetworkSection writes the network configuration section directly to the writer.
func (b *MarkdownBuilder) WriteNetworkSection(w io.Writer, data *model.OpnSenseDocument) error {
	section := b.BuildNetworkSection(data)
	_, err := io.WriteString(w, section)
	return err
}

// WriteSecuritySection writes the security configuration section directly to the writer.
func (b *MarkdownBuilder) WriteSecuritySection(w io.Writer, data *model.OpnSenseDocument) error {
	section := b.BuildSecuritySection(data)
	_, err := io.WriteString(w, section)
	return err
}

// WriteServicesSection writes the services configuration section directly to the writer.
func (b *MarkdownBuilder) WriteServicesSection(w io.Writer, data *model.OpnSenseDocument) error {
	section := b.BuildServicesSection(data)
	_, err := io.WriteString(w, section)
	return err
}

// WriteStandardReport writes a complete standard report directly to the writer.
// Unlike BuildStandardReport which returns a string, this method streams output
// section-by-section, reducing peak memory usage for large configurations.
func (b *MarkdownBuilder) WriteStandardReport(w io.Writer, data *model.OpnSenseDocument) error {
	if data == nil {
		return ErrNilOpnSenseDocument
	}

	// Write header section
	if err := b.writeReportHeader(w, data); err != nil {
		return fmt.Errorf("failed to write report header: %w", err)
	}

	// Write table of contents
	if err := b.writeTableOfContents(w, false); err != nil {
		return fmt.Errorf("failed to write table of contents: %w", err)
	}

	// Write each section directly - no intermediate string accumulation
	if err := b.WriteSystemSection(w, data); err != nil {
		return fmt.Errorf("failed to write system section: %w", err)
	}

	if err := b.WriteNetworkSection(w, data); err != nil {
		return fmt.Errorf("failed to write network section: %w", err)
	}

	if err := b.WriteSecuritySection(w, data); err != nil {
		return fmt.Errorf("failed to write security section: %w", err)
	}

	if err := b.WriteServicesSection(w, data); err != nil {
		return fmt.Errorf("failed to write services section: %w", err)
	}

	// Write additional standard report sections
	if err := b.writeStandardReportFooter(w, data); err != nil {
		return fmt.Errorf("failed to write report footer: %w", err)
	}

	return nil
}

// WriteComprehensiveReport writes a complete comprehensive report directly to the writer.
// This provides the same content as BuildComprehensiveReport but with streaming output.
func (b *MarkdownBuilder) WriteComprehensiveReport(w io.Writer, data *model.OpnSenseDocument) error {
	if data == nil {
		return ErrNilOpnSenseDocument
	}

	// Write header section
	if err := b.writeReportHeader(w, data); err != nil {
		return fmt.Errorf("failed to write report header: %w", err)
	}

	// Write comprehensive table of contents
	if err := b.writeTableOfContents(w, true); err != nil {
		return fmt.Errorf("failed to write table of contents: %w", err)
	}

	// Write each section directly
	if err := b.WriteSystemSection(w, data); err != nil {
		return fmt.Errorf("failed to write system section: %w", err)
	}

	if err := b.WriteNetworkSection(w, data); err != nil {
		return fmt.Errorf("failed to write network section: %w", err)
	}

	// Write VLAN section (Issue #67)
	if _, err := io.WriteString(w, b.buildVLANSection(data)); err != nil {
		return fmt.Errorf("failed to write VLAN section: %w", err)
	}

	// Write Static Routes section (Issue #67)
	if _, err := io.WriteString(w, b.buildStaticRoutesSection(data)); err != nil {
		return fmt.Errorf("failed to write static routes section: %w", err)
	}

	if err := b.WriteSecuritySection(w, data); err != nil {
		return fmt.Errorf("failed to write security section: %w", err)
	}

	// Write IPsec section (Issue #67)
	if _, err := io.WriteString(w, b.BuildIPsecSection(data)); err != nil {
		return fmt.Errorf("failed to write IPsec section: %w", err)
	}

	// Write OpenVPN section (Issue #67)
	if _, err := io.WriteString(w, b.BuildOpenVPNSection(data)); err != nil {
		return fmt.Errorf("failed to write OpenVPN section: %w", err)
	}

	// Write High Availability section (Issue #67)
	if _, err := io.WriteString(w, b.BuildHASection(data)); err != nil {
		return fmt.Errorf("failed to write HA section: %w", err)
	}

	if err := b.WriteServicesSection(w, data); err != nil {
		return fmt.Errorf("failed to write services section: %w", err)
	}

	return nil
}

// writeReportHeader writes the report header (title, system info) to the writer.
func (b *MarkdownBuilder) writeReportHeader(w io.Writer, data *model.OpnSenseDocument) error {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf).
		H1("OPNsense Configuration Summary").
		H2("System Information").
		BulletList(
			markdown.Bold("Hostname")+": "+data.System.Hostname,
			markdown.Bold("Domain")+": "+data.System.Domain,
			markdown.Bold("Platform")+": OPNsense "+data.System.Firmware.Version,
			markdown.Bold("Generated On")+": "+b.getGeneratedTime().Format(time.RFC3339),
			markdown.Bold("Parsed By")+": opnDossier v"+b.getToolVersion(),
		)

	_, err := io.WriteString(w, md.String())
	return err
}

// writeTableOfContents writes the table of contents to the writer.
func (b *MarkdownBuilder) writeTableOfContents(w io.Writer, comprehensive bool) error {
	var buf bytes.Buffer

	// Build ToC items dynamically based on report type
	tocItems := []string{
		markdown.Link("System Configuration", "#system-configuration"),
		markdown.Link("Interfaces", "#interfaces"),
	}

	if comprehensive {
		tocItems = append(tocItems,
			markdown.Link("VLANs", "#vlan-configuration"),
			markdown.Link("Static Routes", "#static-routes"),
		)
	}

	tocItems = append(tocItems,
		markdown.Link("Firewall Rules", "#firewall-rules"),
		markdown.Link("NAT Configuration", "#nat-configuration"),
	)

	if comprehensive {
		tocItems = append(tocItems,
			markdown.Link("IPsec VPN", "#ipsec-vpn-configuration"),
			markdown.Link("OpenVPN", "#openvpn-configuration"),
			markdown.Link("High Availability", "#high-availability--carp"),
		)
	}

	tocItems = append(tocItems,
		markdown.Link("DHCP Services", "#dhcp-services"),
		markdown.Link("DNS Resolver", "#dns-resolver"),
		markdown.Link("System Users", "#system-users"),
	)

	if comprehensive {
		tocItems = append(tocItems, markdown.Link("System Groups", "#system-groups"))
	}

	tocItems = append(tocItems,
		markdown.Link("Services & Daemons", "#services--daemons"),
		markdown.Link("System Tunables", "#system-tunables"),
	)

	md := markdown.NewMarkdown(&buf).
		H2("Table of Contents").
		BulletList(tocItems...)

	_, err := io.WriteString(w, md.String())
	return err
}

// writeStandardReportFooter writes the additional sections for standard reports.
func (b *MarkdownBuilder) writeStandardReportFooter(w io.Writer, data *model.OpnSenseDocument) error {
	sysConfig := data.SystemConfig()

	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	if len(sysConfig.System.User) > 0 {
		md.H2("System Users")
		tableSet := b.BuildUserTable(sysConfig.System.User)
		md.Table(*tableSet)
	}

	if len(sysConfig.Sysctl) > 0 {
		md.H2("System Tunables")
		tableSet := b.BuildSysctlTable(sysConfig.Sysctl)
		md.Table(*tableSet)
	}

	_, err := io.WriteString(w, md.String())
	return err
}

// getGeneratedTime returns the generation timestamp.
func (b *MarkdownBuilder) getGeneratedTime() time.Time {
	if b.generated.IsZero() {
		return time.Now()
	}
	return b.generated
}

// getToolVersion returns the tool version string.
func (b *MarkdownBuilder) getToolVersion() string {
	if b.toolVersion == "" {
		return constants.Version
	}
	return b.toolVersion
}
