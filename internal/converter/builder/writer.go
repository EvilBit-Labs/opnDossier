// Package builder provides programmatic report building functionality for device configurations.
package builder

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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
	WriteSystemSection(w io.Writer, data *common.CommonDevice) error

	// WriteNetworkSection writes the network configuration section to the writer.
	WriteNetworkSection(w io.Writer, data *common.CommonDevice) error

	// WriteSecuritySection writes the security configuration section to the writer.
	WriteSecuritySection(w io.Writer, data *common.CommonDevice) error

	// WriteServicesSection writes the services configuration section to the writer.
	WriteServicesSection(w io.Writer, data *common.CommonDevice) error

	// WriteAuditSection writes the compliance audit section to the writer.
	WriteAuditSection(w io.Writer, data *common.CommonDevice) error

	// WriteStandardReport writes a complete standard report to the writer.
	WriteStandardReport(w io.Writer, data *common.CommonDevice) error

	// WriteComprehensiveReport writes a complete comprehensive report to the writer.
	WriteComprehensiveReport(w io.Writer, data *common.CommonDevice) error
}

// Ensure MarkdownBuilder implements SectionWriter.
var _ SectionWriter = (*MarkdownBuilder)(nil)

// WriteAuditSection writes the compliance audit section directly to the writer.
func (b *MarkdownBuilder) WriteAuditSection(w io.Writer, data *common.CommonDevice) error {
	section := b.BuildAuditSection(data)
	_, err := io.WriteString(w, section)
	return err
}

// WriteSystemSection writes the system configuration section directly to the writer.
func (b *MarkdownBuilder) WriteSystemSection(w io.Writer, data *common.CommonDevice) error {
	section := b.BuildSystemSection(data)
	_, err := io.WriteString(w, section)
	return err
}

// WriteNetworkSection writes the network configuration section directly to the writer.
func (b *MarkdownBuilder) WriteNetworkSection(w io.Writer, data *common.CommonDevice) error {
	section := b.BuildNetworkSection(data)
	_, err := io.WriteString(w, section)
	return err
}

// WriteSecuritySection writes the security configuration section directly to the writer.
func (b *MarkdownBuilder) WriteSecuritySection(w io.Writer, data *common.CommonDevice) error {
	section := b.BuildSecuritySection(data)
	_, err := io.WriteString(w, section)
	return err
}

// WriteServicesSection writes the services configuration section directly to the writer.
func (b *MarkdownBuilder) WriteServicesSection(w io.Writer, data *common.CommonDevice) error {
	section := b.BuildServicesSection(data)
	_, err := io.WriteString(w, section)
	return err
}

// WriteStandardReport writes a complete standard report directly to the writer.
// Unlike BuildStandardReport which returns a string, this method streams output
// section-by-section, reducing peak memory usage for large configurations.
func (b *MarkdownBuilder) WriteStandardReport(w io.Writer, data *common.CommonDevice) error {
	if data == nil {
		return ErrNilDevice
	}

	filteredSysctl := formatters.FilterSystemTunables(data.Sysctl, b.includeTunables)

	// Write header section
	if err := b.writeReportHeader(w, data); err != nil {
		return fmt.Errorf("failed to write report header: %w", err)
	}

	// Write table of contents
	if err := b.writeTableOfContents(w, false, len(filteredSysctl) > 0); err != nil {
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

	// Write tunables footer (users already rendered by WriteSystemSection)
	if err := b.writeStandardReportFooter(w, filteredSysctl); err != nil {
		return fmt.Errorf("failed to write report footer: %w", err)
	}

	return nil
}

// WriteComprehensiveReport writes a complete comprehensive report directly to the writer.
// This provides the same content as BuildComprehensiveReport but with streaming output.
func (b *MarkdownBuilder) WriteComprehensiveReport(w io.Writer, data *common.CommonDevice) error {
	if data == nil {
		return ErrNilDevice
	}

	filteredSysctl := formatters.FilterSystemTunables(data.Sysctl, b.includeTunables)

	// Write header section
	if err := b.writeReportHeader(w, data); err != nil {
		return fmt.Errorf("failed to write report header: %w", err)
	}

	// Write comprehensive table of contents
	if err := b.writeTableOfContents(w, true, len(filteredSysctl) > 0); err != nil {
		return fmt.Errorf("failed to write table of contents: %w", err)
	}

	// Write each section directly
	if err := b.WriteSystemSection(w, data); err != nil {
		return fmt.Errorf("failed to write system section: %w", err)
	}

	if err := b.WriteNetworkSection(w, data); err != nil {
		return fmt.Errorf("failed to write network section: %w", err)
	}

	// Write VLAN section
	if _, err := io.WriteString(w, b.buildVLANSection(data)); err != nil {
		return fmt.Errorf("failed to write VLAN section: %w", err)
	}

	// Write Static Routes section
	if _, err := io.WriteString(w, b.buildStaticRoutesSection(data)); err != nil {
		return fmt.Errorf("failed to write static routes section: %w", err)
	}

	if err := b.WriteSecuritySection(w, data); err != nil {
		return fmt.Errorf("failed to write security section: %w", err)
	}

	// Write IPsec section
	if _, err := io.WriteString(w, b.BuildIPsecSection(data)); err != nil {
		return fmt.Errorf("failed to write IPsec section: %w", err)
	}

	// Write OpenVPN section
	if _, err := io.WriteString(w, b.BuildOpenVPNSection(data)); err != nil {
		return fmt.Errorf("failed to write OpenVPN section: %w", err)
	}

	// Write High Availability section
	if _, err := io.WriteString(w, b.BuildHASection(data)); err != nil {
		return fmt.Errorf("failed to write HA section: %w", err)
	}

	if err := b.WriteServicesSection(w, data); err != nil {
		return fmt.Errorf("failed to write services section: %w", err)
	}

	// Write tunables section
	if len(filteredSysctl) > 0 {
		var buf bytes.Buffer
		md := markdown.NewMarkdown(&buf)
		b.WriteSysctlTable(md.H2("System Tunables"), filteredSysctl)
		if _, err := io.WriteString(w, md.String()); err != nil {
			return fmt.Errorf("failed to write tunables section: %w", err)
		}
	}

	return nil
}

// writeReportHeader writes the report header (title, system info) to the writer.
func (b *MarkdownBuilder) writeReportHeader(w io.Writer, data *common.CommonDevice) error {
	platformName := data.DeviceType.DisplayName()

	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf).
		H1(platformName+" Configuration Summary").
		H2("System Information").
		BulletList(
			markdown.Bold("Hostname")+": "+data.System.Hostname,
			markdown.Bold("Domain")+": "+data.System.Domain,
			markdown.Bold("Platform")+": "+platformName+" "+data.System.Firmware.Version,
			markdown.Bold("Generated On")+": "+b.getGeneratedTime().Format(time.RFC3339),
			markdown.Bold("Parsed By")+": opnDossier v"+b.getToolVersion(),
		)

	_, err := io.WriteString(w, md.String())
	return err
}

// writeTableOfContents writes the table of contents to the writer.
// The hasTunables parameter controls whether the "System Tunables" link is included.
func (b *MarkdownBuilder) writeTableOfContents(w io.Writer, comprehensive, hasTunables bool) error {
	var buf bytes.Buffer

	var tocItems []string
	if comprehensive {
		tocItems = b.comprehensiveToCItems(hasTunables)
	} else {
		tocItems = b.standardToCItems(hasTunables)
	}

	md := markdown.NewMarkdown(&buf).
		H2("Table of Contents").
		BulletList(tocItems...)

	_, err := io.WriteString(w, md.String())
	return err
}

// writeStandardReportFooter writes system tunables for standard reports.
// Users are already rendered by WriteSystemSection — this avoids duplication.
// The filteredSysctl parameter is the pre-filtered tunables slice.
func (b *MarkdownBuilder) writeStandardReportFooter(
	w io.Writer,
	filteredSysctl []common.SysctlItem,
) error {
	if len(filteredSysctl) == 0 {
		return nil
	}

	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.WriteSysctlTable(md.H2("System Tunables"), filteredSysctl)

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
