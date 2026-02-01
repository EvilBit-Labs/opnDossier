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
	md := markdown.NewMarkdown(&buf)

	md.H1("OPNsense Configuration Summary")

	md.H2("System Information")
	md.PlainTextf("- **Hostname**: %s", data.System.Hostname)
	md.PlainTextf("- **Domain**: %s", data.System.Domain)
	md.PlainTextf("- **Platform**: OPNsense %s", data.System.Firmware.Version)
	md.PlainTextf("- **Generated On**: %s", b.getGeneratedTime().Format(time.RFC3339))
	md.PlainTextf("- **Parsed By**: opnDossier v%s", b.getToolVersion())

	_, err := io.WriteString(w, md.String())
	return err
}

// writeTableOfContents writes the table of contents to the writer.
func (b *MarkdownBuilder) writeTableOfContents(w io.Writer, comprehensive bool) error {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)

	md.H2("Table of Contents")
	md.PlainText("- [System Configuration](#system-configuration)")
	md.PlainText("- [Interfaces](#interfaces)")

	if comprehensive {
		md.PlainText("- [VLANs](#vlan-configuration)")
		md.PlainText("- [Static Routes](#static-routes)")
	}

	md.PlainText("- [Firewall Rules](#firewall-rules)")
	md.PlainText("- [NAT Configuration](#nat-configuration)")

	if comprehensive {
		md.PlainText("- [IPsec VPN](#ipsec-vpn-configuration)")
		md.PlainText("- [OpenVPN](#openvpn-configuration)")
		md.PlainText("- [High Availability](#high-availability--carp)")
	}

	md.PlainText("- [DHCP Services](#dhcp-services)")
	md.PlainText("- [DNS Resolver](#dns-resolver)")
	md.PlainText("- [System Users](#system-users)")

	if comprehensive {
		md.PlainText("- [System Groups](#system-groups)")
	}

	md.PlainText("- [Services & Daemons](#services--daemons)")
	md.PlainText("- [System Tunables](#system-tunables)")

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
