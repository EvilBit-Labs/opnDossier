package processor

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"gopkg.in/yaml.v3"
)

// redactedValue is the placeholder for sensitive fields in processor report output.
const redactedValue = "[REDACTED]"

// Report contains the results of processing a device configuration.
// It includes the normalized configuration, analysis findings, and statistics.
type Report struct {
	mu sync.RWMutex `json:"-" yaml:"-"` // protects Findings for concurrent access

	// DeviceType identifies the platform at the top level for easy access
	DeviceType common.DeviceType `json:"device_type" yaml:"device_type"`

	// GeneratedAt contains the timestamp when the report was generated
	GeneratedAt time.Time `json:"generatedAt"`

	// ConfigInfo contains basic information about the processed configuration
	ConfigInfo ConfigInfo `json:"configInfo"`

	// NormalizedConfig contains the processed and normalized configuration
	NormalizedConfig *common.CommonDevice `json:"normalizedConfig,omitempty"`

	// Statistics contains various statistics about the configuration
	Statistics *Statistics `json:"statistics,omitempty"`

	// Findings contains analysis findings categorized by type
	Findings Findings `json:"findings"`

	// ProcessorConfig contains the configuration used during processing
	ProcessorConfig Config `json:"processorConfig"`
}

// ConfigInfo contains basic information about the processed configuration.
type ConfigInfo struct {
	// Hostname is the configured hostname of the system
	Hostname string `json:"hostname"`
	// Domain is the configured domain name
	Domain string `json:"domain"`
	// Version is the firmware version (if available)
	Version string `json:"version,omitempty"`
	// Theme is the configured web UI theme
	Theme string `json:"theme,omitempty"`
	// DeviceType identifies the platform
	DeviceType common.DeviceType `json:"deviceType,omitempty"`
}

// Findings contains analysis findings categorized by severity and type.
type Findings struct {
	// Critical findings that require immediate attention
	Critical []Finding `json:"critical,omitempty"`
	// High severity findings
	High []Finding `json:"high,omitempty"`
	// Medium severity findings
	Medium []Finding `json:"medium,omitempty"`
	// Low severity findings
	Low []Finding `json:"low,omitempty"`
	// Informational findings
	Info []Finding `json:"info,omitempty"`
}

// Finding is a type alias for the canonical analysis.Finding type.
// This ensures the processor package uses the same finding structure as
// compliance and audit packages.
type Finding = analysis.Finding

// Severity is a type alias for the canonical analysis.Severity type.
type Severity = analysis.Severity

// Severity constants re-exported from the canonical analysis package.
const (
	// SeverityCritical represents critical findings that require immediate attention.
	SeverityCritical = analysis.SeverityCritical
	// SeverityHigh represents high-severity findings that should be addressed soon.
	SeverityHigh = analysis.SeverityHigh
	// SeverityMedium represents medium-severity findings worth investigating.
	SeverityMedium = analysis.SeverityMedium
	// SeverityLow represents low-severity findings for general improvement.
	SeverityLow = analysis.SeverityLow
	// SeverityInfo represents informational findings with no immediate action required.
	SeverityInfo = analysis.SeverityInfo
)

// NewReport returns a new Report instance populated with configuration metadata, processor settings, and optionally generated statistics and normalized configuration data.
func NewReport(cfg *common.CommonDevice, processorConfig Config) *Report {
	report := &Report{
		GeneratedAt:     time.Now().UTC(),
		ProcessorConfig: processorConfig,
		Findings: Findings{
			Critical: make([]Finding, 0),
			High:     make([]Finding, 0),
			Medium:   make([]Finding, 0),
			Low:      make([]Finding, 0),
			Info:     make([]Finding, 0),
		},
	}

	if cfg != nil {
		report.ConfigInfo = ConfigInfo{
			Hostname:   cfg.System.Hostname,
			Domain:     cfg.System.Domain,
			Version:    cfg.Version,
			Theme:      cfg.Theme,
			DeviceType: cfg.DeviceType,
		}

		report.DeviceType = cfg.DeviceType

		if processorConfig.EnableStats {
			report.Statistics = generateStatistics(cfg)
		}

		// Store normalized config if requested (could be controlled by an option)
		report.NormalizedConfig = cfg
	}

	return report
}

// AddFinding adds a finding to the report with the specified severity.
func (r *Report) AddFinding(severity Severity, finding Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch severity {
	case SeverityCritical:
		r.Findings.Critical = append(r.Findings.Critical, finding)
	case SeverityHigh:
		r.Findings.High = append(r.Findings.High, finding)
	case SeverityMedium:
		r.Findings.Medium = append(r.Findings.Medium, finding)
	case SeverityLow:
		r.Findings.Low = append(r.Findings.Low, finding)
	case SeverityInfo:
		r.Findings.Info = append(r.Findings.Info, finding)
	}
}

// TotalFindings returns the total number of findings across all severities.
func (r *Report) TotalFindings() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.totalFindingsUnsafe()
}

// totalFindingsUnsafe returns total findings without locking. Caller must hold mu.
func (r *Report) totalFindingsUnsafe() int {
	return len(r.Findings.Critical) + len(r.Findings.High) +
		len(r.Findings.Medium) + len(r.Findings.Low) + len(r.Findings.Info)
}

// HasCriticalFindings returns true if the report contains critical findings.
func (r *Report) HasCriticalFindings() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.Findings.Critical) > 0
}

// OutputFormat represents the supported output formats.
type OutputFormat string

// Supported output format constants for report generation.
const (
	// OutputFormatMarkdown outputs the report as Markdown.
	OutputFormatMarkdown OutputFormat = "markdown"
	// OutputFormatJSON outputs the report as JSON.
	OutputFormatJSON OutputFormat = "json"
	// OutputFormatYAML outputs the report as YAML.
	OutputFormatYAML OutputFormat = "yaml"
)

// ToFormat returns the report in the specified format.
func (r *Report) ToFormat(format OutputFormat) (string, error) {
	switch format {
	case OutputFormatMarkdown:
		return r.ToMarkdown(), nil
	case OutputFormatJSON:
		return r.ToJSON()
	case OutputFormatYAML:
		return r.ToYAML()
	default:
		return "", &UnsupportedFormatError{Format: string(format)}
	}
}

// ToJSON returns the report as a JSON string.
// NormalizedConfig is redacted before serialization to prevent leaking secrets.
func (r *Report) ToJSON() (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	safe := r.redactedCopyUnsafe()
	//nolint:musttag // Report has proper json tags
	data, err := json.MarshalIndent(safe, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	return string(data), nil
}

// ToYAML returns the report as a YAML string.
// NormalizedConfig is redacted before serialization to prevent leaking secrets.
func (r *Report) ToYAML() (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	safe := r.redactedCopyUnsafe()
	//nolint:musttag // Report has proper yaml tags
	data, err := yaml.Marshal(safe)
	if err != nil {
		return "", fmt.Errorf("failed to marshal report to YAML: %w", err)
	}

	return string(data), nil
}

// redactedCopyUnsafe returns a shallow copy of the Report with sensitive fields
// in NormalizedConfig replaced by the redaction marker. The caller's original
// CommonDevice is never mutated. The mu field is omitted (json:"-" / yaml:"-")
// so the copy does not need a live mutex. Caller must hold mu.
func (r *Report) redactedCopyUnsafe() *Report {
	cp := &Report{
		DeviceType:       r.DeviceType,
		GeneratedAt:      r.GeneratedAt,
		ConfigInfo:       r.ConfigInfo,
		NormalizedConfig: r.NormalizedConfig,
		Statistics:       r.Statistics,
		Findings:         r.Findings,
		ProcessorConfig:  r.ProcessorConfig,
	}

	if cp.NormalizedConfig != nil {
		needsRedaction := cp.NormalizedConfig.SNMP.ROCommunity != "" ||
			hasCertPrivateKeys(cp.NormalizedConfig.Certificates) ||
			hasCAPrivateKeys(cp.NormalizedConfig.CAs)

		if needsRedaction {
			deviceCopy := *cp.NormalizedConfig
			cp.NormalizedConfig = &deviceCopy

			if deviceCopy.SNMP.ROCommunity != "" {
				deviceCopy.SNMP = common.SNMPConfig{
					ROCommunity: redactedValue,
					SysLocation: deviceCopy.SNMP.SysLocation,
					SysContact:  deviceCopy.SNMP.SysContact,
				}
			}

			if len(deviceCopy.Certificates) > 0 {
				certs := make([]common.Certificate, len(deviceCopy.Certificates))
				copy(certs, deviceCopy.Certificates)

				for i := range certs {
					if certs[i].PrivateKey != "" {
						certs[i].PrivateKey = redactedValue
					}
				}

				deviceCopy.Certificates = certs
			}

			if len(deviceCopy.CAs) > 0 {
				cas := make([]common.CertificateAuthority, len(deviceCopy.CAs))
				copy(cas, deviceCopy.CAs)

				for i := range cas {
					if cas[i].PrivateKey != "" {
						cas[i].PrivateKey = redactedValue
					}
				}

				deviceCopy.CAs = cas
			}
		}
	}

	return cp
}

// hasCertPrivateKeys reports whether any certificate in the slice has a
// non-empty PrivateKey.
func hasCertPrivateKeys(certs []common.Certificate) bool {
	for i := range certs {
		if certs[i].PrivateKey != "" {
			return true
		}
	}

	return false
}

// hasCAPrivateKeys reports whether any CA in the slice has a non-empty
// PrivateKey.
func hasCAPrivateKeys(cas []common.CertificateAuthority) bool {
	for i := range cas {
		if cas[i].PrivateKey != "" {
			return true
		}
	}

	return false
}
