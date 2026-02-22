package processor

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validationFindingType = "validation"

func TestValidateCommonDevice(t *testing.T) {
	t.Parallel()

	validInterfaces := []common.Interface{
		{Name: "wan", IPAddress: "192.168.1.1", Subnet: "24"},
		{Name: "lan", IPAddress: "10.0.0.1", Subnet: "24"},
	}

	tests := []struct {
		name         string
		cfg          *common.CommonDevice
		wantErrCount int
		minErrs      bool
		wantFields   []string
	}{
		{
			name:         "nil config",
			cfg:          nil,
			wantErrCount: 1,
			wantFields:   []string{"document"},
		},
		{
			name: "valid minimal",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: validInterfaces,
			},
			wantErrCount: 0,
		},
		{
			name: "empty hostname",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "", Domain: "example.com"},
				Interfaces: validInterfaces,
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"system.hostname"},
		},
		{
			name: "invalid hostname chars",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "bad host!", Domain: "example.com"},
				Interfaces: validInterfaces,
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"system.hostname"},
		},
		{
			name: "invalid IP on interface",
			cfg: &common.CommonDevice{
				System: common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: []common.Interface{
					{Name: "wan", IPAddress: "999.1.1.1", Subnet: "24"},
					{Name: "lan", IPAddress: "10.0.0.1", Subnet: "24"},
				},
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"ipAddress"},
		},
		{
			name: "invalid subnet",
			cfg: &common.CommonDevice{
				System: common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: []common.Interface{
					{Name: "wan", IPAddress: "192.168.1.1", Subnet: "33"},
					{Name: "lan", IPAddress: "10.0.0.1", Subnet: "24"},
				},
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"subnet"},
		},
		{
			name: "DHCP range inverted",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: validInterfaces,
				DHCP: []common.DHCPScope{
					{
						Interface: "lan",
						Range: common.DHCPRange{
							From: "10.0.0.200",
							To:   "10.0.0.100",
						},
					},
				},
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"range"},
		},
		{
			name: "DHCP unknown interface",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: validInterfaces,
				DHCP: []common.DHCPScope{
					{Interface: "opt1"},
				},
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"interface"},
		},
		{
			name: "invalid firewall type",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: validInterfaces,
				FirewallRules: []common.FirewallRule{
					{Type: "allow", Interfaces: []string{"lan"}, IPProtocol: "inet"},
				},
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"type"},
		},
		{
			name: "firewall unknown interface",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: validInterfaces,
				FirewallRules: []common.FirewallRule{
					{Type: "pass", Interfaces: []string{"opt1"}, IPProtocol: "inet"},
				},
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"interfaces"},
		},
		{
			name: "duplicate user name",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: validInterfaces,
				Users: []common.User{
					{Name: "alice", UID: "1000"},
					{Name: "alice", UID: "1001"},
				},
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"name"},
		},
		{
			name: "duplicate user UID",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: validInterfaces,
				Users: []common.User{
					{Name: "alice", UID: "1000"},
					{Name: "bob", UID: "1000"},
				},
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"uid"},
		},
		{
			name: "user references unknown group",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: validInterfaces,
				Users: []common.User{
					{Name: "alice", UID: "1000", GroupName: "admins"},
				},
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"groupName"},
		},
		{
			name: "invalid sysctl name",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: validInterfaces,
				Sysctl: []common.SysctlItem{
					{Tunable: "no-dot", Value: "1"},
				},
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"tunable"},
		},
		{
			name: "duplicate sysctl tunable",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: validInterfaces,
				Sysctl: []common.SysctlItem{
					{Tunable: "net.inet.ip.forwarding", Value: "1"},
					{Tunable: "net.inet.ip.forwarding", Value: "0"},
				},
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"tunable"},
		},
		{
			name: "invalid NAT outbound mode",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "fw", Domain: "example.com"},
				Interfaces: validInterfaces,
				NAT:        common.NATConfig{OutboundMode: "bogus"},
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"nat.outboundMode"},
		},
		{
			name: "invalid optimization",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "fw", Domain: "example.com", Optimization: "turbo"},
				Interfaces: validInterfaces,
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"system.optimization"},
		},
		{
			name: "invalid bogons interval",
			cfg: &common.CommonDevice{
				System: common.System{
					Hostname: "fw",
					Domain:   "example.com",
					Bogons:   common.Bogons{Interval: "hourly"},
				},
				Interfaces: validInterfaces,
			},
			wantErrCount: 1,
			minErrs:      true,
			wantFields:   []string{"system.bogons.interval"},
		},
		{
			name: "multiple errors accumulate",
			cfg: &common.CommonDevice{
				System:     common.System{Hostname: "", Domain: "example.com"},
				Interfaces: validInterfaces,
				DHCP: []common.DHCPScope{
					{
						Interface: "lan",
						Range: common.DHCPRange{
							From: "10.0.0.200",
							To:   "10.0.0.100",
						},
					},
				},
			},
			wantErrCount: 2,
			minErrs:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			errs := ValidateCommonDevice(tt.cfg)
			if tt.minErrs {
				assert.GreaterOrEqual(t, len(errs), tt.wantErrCount)
			} else {
				assert.Len(t, errs, tt.wantErrCount)
			}

			for _, expectedField := range tt.wantFields {
				found := false
				for _, err := range errs {
					if strings.Contains(err.Field, expectedField) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected field %q in validation errors", expectedField)
			}
		})
	}
}

func TestCoreProcessor_PanicRecovery(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logging.New(logging.Config{Output: &buf, Level: "error"})
	require.NoError(t, err)

	processor, err := NewCoreProcessor(logger)
	require.NoError(t, err)

	processor.validateFn = func(_ *common.CommonDevice) []ValidationError {
		panic("injected test panic")
	}

	cfg := &common.CommonDevice{
		System: common.System{Hostname: "fw", Domain: "example.com"},
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "192.168.1.1", Subnet: "24"},
			{Name: "lan", IPAddress: "10.0.0.1", Subnet: "24"},
		},
	}

	report, err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.GreaterOrEqual(t, len(report.Findings.Critical), 1)

	foundValidation := false
	for _, finding := range report.Findings.Critical {
		if finding.Type == validationFindingType && strings.Contains(finding.Description, "panicked:") {
			foundValidation = true
			break
		}
	}
	assert.True(t, foundValidation, "expected critical validation finding with panic description")
	assert.Contains(t, buf.String(), "validation panic recovered")
}

func TestCoreProcessor_ValidationSeverity(t *testing.T) {
	processor, err := NewCoreProcessor(nil)
	require.NoError(t, err)

	cfg := &common.CommonDevice{
		System: common.System{Hostname: "fw", Domain: "example.com", Optimization: "turbo"},
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "192.168.1.1", Subnet: "24"},
			{Name: "lan", IPAddress: "10.0.0.1", Subnet: "24"},
		},
	}

	report, err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, report)

	foundValidation := false
	for _, finding := range report.Findings.High {
		if finding.Type == validationFindingType {
			foundValidation = true
			assert.Equal(t, "system.optimization", finding.Component)
			break
		}
	}
	assert.True(t, foundValidation, "expected validation finding with high severity")

	infoValidation := 0
	for _, finding := range report.Findings.Info {
		if finding.Type == validationFindingType {
			infoValidation++
		}
	}
	assert.Equal(t, 0, infoValidation)
}
