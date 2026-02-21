package processor

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const complianceFindingType = "compliance"

func TestExampleProcessor_ComplianceChecks(t *testing.T) {
	processor := NewExampleProcessor()
	ctx := context.Background()

	tests := []struct {
		name               string
		config             *common.CommonDevice
		expectedBySeverity map[Severity]int
		expectedTitles     []string
		expectedComponents map[string]string
	}{
		{
			name: "No administrative users configured",
			config: func() *common.CommonDevice {
				cfg := baseComplianceConfig()
				cfg.Users = nil
				return cfg
			}(),
			expectedBySeverity: map[Severity]int{
				SeverityCritical: 1,
			},
			expectedTitles: []string{
				"No Administrative Users Configured",
			},
			expectedComponents: map[string]string{
				"No Administrative Users Configured": "users",
			},
		},
		{
			name: "Disabled administrative users",
			config: func() *common.CommonDevice {
				cfg := baseComplianceConfig()
				cfg.Users = []common.User{
					buildUser("ops-admin", "admins", "local", true),
				}
				return cfg
			}(),
			expectedBySeverity: map[Severity]int{
				SeverityCritical: 1,
				SeverityMedium:   1,
			},
			expectedTitles: []string{
				"No Administrative Users Configured",
				"Weak User Account Configuration",
			},
			expectedComponents: map[string]string{
				"No Administrative Users Configured": "users",
				"Weak User Account Configuration":    "users",
			},
		},
		{
			name: "Non-admin users",
			config: func() *common.CommonDevice {
				cfg := baseComplianceConfig()
				cfg.Users = []common.User{
					buildUser("analyst", "users", "local", false),
					buildUser("admin", "admins", "local", false),
				}
				return cfg
			}(),
			expectedBySeverity: map[Severity]int{},
			expectedTitles:     nil,
		},
		{
			name: "Non-local admin",
			config: func() *common.CommonDevice {
				cfg := baseComplianceConfig()
				cfg.Users = []common.User{
					buildUser("remote-admin", "admins", "system", false),
					buildUser("admin", "admins", "local", false),
				}
				return cfg
			}(),
			expectedBySeverity: map[Severity]int{},
			expectedTitles:     nil,
		},
		{
			name:               "Valid user configuration",
			config:             baseComplianceConfig(),
			expectedBySeverity: map[Severity]int{},
			expectedTitles:     nil,
		},
		{
			name: "Syslog disabled",
			config: func() *common.CommonDevice {
				cfg := baseComplianceConfig()
				cfg.Syslog = buildSyslogConfig(false, false, false, false, false)
				return cfg
			}(),
			expectedBySeverity: map[Severity]int{
				SeverityHigh: 1,
			},
			expectedTitles: []string{
				"Audit Logging Not Configured",
			},
			expectedComponents: map[string]string{
				"Audit Logging Not Configured": "syslog",
			},
		},
		{
			name: "Syslog missing critical categories",
			config: func() *common.CommonDevice {
				cfg := baseComplianceConfig()
				cfg.Syslog = buildSyslogConfig(true, true, false, false, true)
				return cfg
			}(),
			expectedBySeverity: map[Severity]int{
				SeverityMedium: 1,
			},
			expectedTitles: []string{
				"Incomplete Audit Logging",
			},
			expectedComponents: map[string]string{
				"Incomplete Audit Logging": "syslog",
			},
		},
		{
			name: "Syslog configured without remote server",
			config: func() *common.CommonDevice {
				cfg := baseComplianceConfig()
				cfg.Syslog = buildSyslogConfig(true, true, true, true, false)
				return cfg
			}(),
			expectedBySeverity: map[Severity]int{
				SeverityLow: 1,
			},
			expectedTitles: []string{
				"Remote Audit Logging Not Configured",
			},
			expectedComponents: map[string]string{
				"Remote Audit Logging Not Configured": "syslog",
			},
		},
		{
			name:               "Syslog fully configured with remote",
			config:             baseComplianceConfig(),
			expectedBySeverity: map[Severity]int{},
			expectedTitles:     nil,
		},
		{
			name: "Partial logging configuration",
			config: func() *common.CommonDevice {
				cfg := baseComplianceConfig()
				cfg.Syslog = buildSyslogConfig(true, false, true, false, false)
				return cfg
			}(),
			expectedBySeverity: map[Severity]int{
				SeverityMedium: 1,
				SeverityLow:    1,
			},
			expectedTitles: []string{
				"Incomplete Audit Logging",
				"Remote Audit Logging Not Configured",
			},
			expectedComponents: map[string]string{
				"Incomplete Audit Logging":            "syslog",
				"Remote Audit Logging Not Configured": "syslog",
			},
		},
		{
			name: "Syslog disabled finding",
			config: func() *common.CommonDevice {
				cfg := baseComplianceConfig()
				cfg.Users = []common.User{
					buildUser("admin", "admins", "local", false),
				}
				cfg.Syslog = buildSyslogConfig(false, false, false, false, false)
				return cfg
			}(),
			expectedBySeverity: map[Severity]int{
				SeverityHigh: 1,
			},
			expectedTitles: []string{
				"Audit Logging Not Configured",
			},
			expectedComponents: map[string]string{
				"Audit Logging Not Configured": "syslog",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := processor.Process(ctx, tt.config, WithComplianceCheck())
			require.NoError(t, err)
			require.NotNil(t, report)

			severityCounts := complianceFindingsBySeverity(report)
			for severity, expected := range tt.expectedBySeverity {
				assert.Equal(t, expected, severityCounts[severity], "unexpected %s compliance findings", severity)
			}

			for _, title := range tt.expectedTitles {
				finding, found := findComplianceFinding(report, title)
				require.True(t, found, "expected finding %q", title)
				assert.NotEmpty(t, finding.Description)
				assert.NotEmpty(t, finding.Recommendation)
				assert.Equal(t, complianceFindingType, finding.Type)
				if component, ok := tt.expectedComponents[title]; ok {
					assert.Equal(t, component, finding.Component)
				}
			}
		})
	}
}

func baseComplianceConfig() *common.CommonDevice {
	return &common.CommonDevice{
		System: common.System{
			Hostname:    "test-firewall",
			Domain:      "example.com",
			WebGUI:      common.WebGUI{Protocol: "https"},
			TimeServers: []string{"pool.ntp.org"},
		},
		Users: []common.User{
			buildUser("admin", "admins", "local", false),
		},
		Syslog: buildSyslogConfig(true, true, true, true, true),
	}
}

func buildUser(name, group, scope string, disabled bool) common.User {
	return common.User{
		Name:      name,
		GroupName: group,
		UID:       "1000",
		Scope:     scope,
		Disabled:  disabled,
	}
}

func buildSyslogConfig(enabled, system, auth, filter, remote bool) common.SyslogConfig {
	syslog := common.SyslogConfig{
		Enabled:       enabled,
		SystemLogging: system,
		AuthLogging:   auth,
		FilterLogging: filter,
	}

	if remote {
		syslog.RemoteServer = "10.0.0.10"
	}

	return syslog
}

func allFindingsBySeverity(report *Report) []struct {
	severity Severity
	findings []Finding
} {
	return []struct {
		severity Severity
		findings []Finding
	}{
		{SeverityCritical, report.Findings.Critical},
		{SeverityHigh, report.Findings.High},
		{SeverityMedium, report.Findings.Medium},
		{SeverityLow, report.Findings.Low},
		{SeverityInfo, report.Findings.Info},
	}
}

func complianceFindingsBySeverity(report *Report) map[Severity]int {
	counts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}

	for _, sf := range allFindingsBySeverity(report) {
		for _, finding := range sf.findings {
			if finding.Type == complianceFindingType {
				counts[sf.severity]++
			}
		}
	}

	return counts
}

func findComplianceFinding(report *Report, title string) (Finding, bool) {
	for _, sf := range allFindingsBySeverity(report) {
		for _, finding := range sf.findings {
			if finding.Type == complianceFindingType && finding.Title == title {
				return finding, true
			}
		}
	}

	return Finding{}, false
}
