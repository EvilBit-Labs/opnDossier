package parser

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// TestXMLParser_ValidateRequiredElements tests validation of missing required elements.
func TestXMLParser_ValidateRequiredElements(t *testing.T) {
	tests := []struct {
		name           string
		config         *model.OpnSenseDocument
		expectedErrors int
		expectedFields []string
		description    string
	}{
		{
			name: "missing hostname",
			config: &model.OpnSenseDocument{
				System: model.System{
					Domain: "example.com",
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.hostname"},
			description:    "Hostname is required and must be present",
		},
		{
			name: "missing domain",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.domain"},
			description:    "Domain is required and must be present",
		},
		{
			name: "missing both hostname and domain",
			config: &model.OpnSenseDocument{
				System: model.System{
					Optimization: "normal",
				},
			},
			expectedErrors: 2,
			expectedFields: []string{"opnsense.system.hostname", "opnsense.system.domain"},
			description:    "Both hostname and domain are required",
		},
		{
			name: "missing group name",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					Group: []model.Group{
						{
							Gid:   "1000",
							Scope: "system",
						},
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.group[0].name"},
			description:    "Group name is required",
		},
		{
			name: "missing group GID",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					Group: []model.Group{
						{
							Name:  "testgroup",
							Scope: "system",
						},
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.group[0].gid"},
			description:    "Group GID is required",
		},
		{
			name: "missing user name",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					Group: []model.Group{
						{
							Name: "admin",
							Gid:  "1000",
						},
					},
					User: []model.User{
						{
							UID:       "1000",
							Groupname: "admin",
						},
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.user[0].name"},
			description:    "User name is required",
		},
		{
			name: "missing user UID",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					Group: []model.Group{
						{
							Name: "admin",
							Gid:  "1000",
						},
					},
					User: []model.User{
						{
							Name:      "testuser",
							Groupname: "admin",
						},
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.user[0].uid"},
			description:    "User UID is required",
		},
		{
			name: "missing sysctl tunable",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
				},
				Sysctl: []model.SysctlItem{
					{
						Value: "1",
						Descr: "Test sysctl",
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.sysctl[0].tunable"},
			description:    "Sysctl tunable name is required",
		},
		{
			name: "missing sysctl value",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
				},
				Sysctl: []model.SysctlItem{
					{
						Tunable: "net.inet.ip.random_id",
						Descr:   "Test sysctl",
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.sysctl[0].value"},
			description:    "Sysctl value is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewXMLParser()
			err := parser.Validate(tt.config)

			if tt.expectedErrors == 0 {
				assert.NoError(t, err, tt.description)
				return
			}

			require.Error(t, err, tt.description)

			// Check if it's an AggregatedValidationError
			var aggErr *AggregatedValidationError
			require.ErrorAs(t, err, &aggErr, "Expected AggregatedValidationError")

			assert.Len(t, aggErr.Errors, tt.expectedErrors, "Expected number of validation errors")

			// Check that all expected fields are present in errors
			actualFields := make([]string, len(aggErr.Errors))
			for i, validationErr := range aggErr.Errors {
				actualFields[i] = validationErr.Path
			}

			for _, expectedField := range tt.expectedFields {
				assert.Contains(t, actualFields, expectedField, "Expected field %s in validation errors", expectedField)
			}
		})
	}
}

// TestXMLParser_ValidateInvalidEnumValues tests validation of invalid enum values.
func TestXMLParser_ValidateInvalidEnumValues(t *testing.T) {
	tests := []struct {
		name           string
		config         *model.OpnSenseDocument
		expectedErrors int
		expectedFields []string
		description    string
	}{
		{
			name: "invalid system optimization",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname:     "testhost",
					Domain:       "example.com",
					Optimization: "invalid-optimization",
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.optimization"},
			description:    "Optimization must be one of: normal, high-latency, aggressive, conservative",
		},
		{
			name: "invalid webgui protocol",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					WebGUI: struct {
						Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
						SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
					}{Protocol: "ftp"},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.webgui.protocol"},
			description:    "Webgui protocol must be http or https",
		},
		{
			name: "invalid power management mode",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname:         "testhost",
					Domain:           "example.com",
					PowerdACMode:     "invalid-mode",
					PowerdNormalMode: "another-invalid",
				},
			},
			expectedErrors: 2,
			expectedFields: []string{"opnsense.system.powerd_ac_mode", "opnsense.system.powerd_normal_mode"},
			description:    "Power management modes must be valid",
		},
		{
			name: "invalid bogons interval",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					Bogons: struct {
						Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
					}{Interval: "invalid-interval"},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.bogons.interval"},
			description:    "Bogons interval must be monthly, weekly, daily, or never",
		},
		{
			name: "invalid firewall rule type",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
				},
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type:       "invalid-type",
							IPProtocol: "inet",
							Interface:  "lan",
						},
					},
				},
			},
			expectedErrors: 2,
			expectedFields: []string{"opnsense.filter.rule[0].type", "opnsense.filter.rule[0].interface"},
			description:    "Rule type must be pass, block, or reject",
		},
		{
			name: "invalid IP protocol",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
				},
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type:       "pass",
							IPProtocol: "invalid-protocol",
							Interface:  "lan",
						},
					},
				},
			},
			expectedErrors: 2,
			expectedFields: []string{"opnsense.filter.rule[0].ipprotocol", "opnsense.filter.rule[0].interface"},
			description:    "IP protocol must be inet or inet6",
		},
		{
			name: "invalid interface name",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
				},
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type:       "pass",
							IPProtocol: "inet",
							Interface:  "invalid-interface",
						},
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.filter.rule[0].interface"},
			description:    "Interface must be wan, lan, opt1, opt2, opt3, or opt4",
		},
		{
			name: "invalid NAT outbound mode",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
				},
				Nat: model.Nat{
					Outbound: model.Outbound{
						Mode: "invalid-mode",
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.nat.outbound.mode"},
			description:    "NAT outbound mode must be automatic, hybrid, advanced, or disabled",
		},
		{
			name: "invalid group scope",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					Group: []model.Group{
						{
							Name:  "testgroup",
							Gid:   "1000",
							Scope: "invalid-scope",
						},
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.group[0].scope"},
			description:    "Group scope must be system or local",
		},
		{
			name: "invalid user scope",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					User: []model.User{
						{
							Name:  "testuser",
							UID:   "1000",
							Scope: "invalid-scope",
						},
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.user[0].scope"},
			description:    "User scope must be system or local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewXMLParser()
			err := parser.Validate(tt.config)

			require.Error(t, err, tt.description)

			// Check if it's an AggregatedValidationError
			var aggErr *AggregatedValidationError
			require.ErrorAs(t, err, &aggErr, "Expected AggregatedValidationError")

			assert.Len(t, aggErr.Errors, tt.expectedErrors, "Expected number of validation errors")

			// Check that all expected fields are present in errors
			actualFields := make([]string, len(aggErr.Errors))
			for i, validationErr := range aggErr.Errors {
				actualFields[i] = validationErr.Path
			}

			for _, expectedField := range tt.expectedFields {
				assert.Contains(t, actualFields, expectedField, "Expected field %s in validation errors", expectedField)
			}
		})
	}
}

// TestXMLParser_ValidateCrossFieldMismatches tests cross-field validation mismatches.
func TestXMLParser_ValidateCrossFieldMismatches(t *testing.T) {
	tests := []struct {
		name           string
		config         *model.OpnSenseDocument
		expectedErrors int
		expectedFields []string
		description    string
	}{
		{
			name: "track6 without required fields",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"lan": {
							IPAddrv6: "track6",
							// Missing Track6Interface and Track6PrefixID
						},
					},
				},
			},
			expectedErrors: 2,
			expectedFields: []string{"opnsense.interfaces.lan.track6-interface", "opnsense.interfaces.lan.track6-prefix-id"},
			description:    "track6 IPv6 addressing requires track6-interface and track6-prefix-id",
		},
		{
			name: "DHCP range with invalid order",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
				},
				Dhcpd: model.Dhcpd{
					Items: map[string]model.DhcpdInterface{
						"lan": {
							Range: model.Range{
								From: "192.168.1.200",
								To:   "192.168.1.100", // From > To
							},
						},
					},
				},
			},
			expectedErrors: 2,
			expectedFields: []string{"opnsense.dhcpd.lan.range", "opnsense.dhcpd.lan"},
			description:    "DHCP range 'from' address must be less than 'to' address",
		},
		{
			name: "user referencing non-existent group",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					Group: []model.Group{
						{
							Name: "admin",
							Gid:  "1000",
						},
					},
					User: []model.User{
						{
							Name:      "testuser",
							UID:       "1001",
							Groupname: "nonexistent", // Group doesn't exist
						},
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.user[0].groupname"},
			description:    "User must reference an existing group",
		},
		{
			name: "duplicate group names",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					Group: []model.Group{
						{
							Name: "admin",
							Gid:  "1000",
						},
						{
							Name: "admin", // Duplicate name
							Gid:  "1001",
						},
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.group[1].name"},
			description:    "Group names must be unique",
		},
		{
			name: "duplicate group GIDs",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					Group: []model.Group{
						{
							Name: "admin",
							Gid:  "1000",
						},
						{
							Name: "users",
							Gid:  "1000", // Duplicate GID
						},
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.group[1].gid"},
			description:    "Group GIDs must be unique",
		},
		{
			name: "duplicate user names",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					Group: []model.Group{
						{
							Name: "admin",
							Gid:  "1000",
						},
					},
					User: []model.User{
						{
							Name:      "root",
							UID:       "0",
							Groupname: "admin",
						},
						{
							Name:      "root", // Duplicate name
							UID:       "1001",
							Groupname: "admin",
						},
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.user[1].name"},
			description:    "User names must be unique",
		},
		{
			name: "duplicate user UIDs",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					Group: []model.Group{
						{
							Name: "admin",
							Gid:  "1000",
						},
					},
					User: []model.User{
						{
							Name:      "root",
							UID:       "0",
							Groupname: "admin",
						},
						{
							Name:      "admin",
							UID:       "0", // Duplicate UID
							Groupname: "admin",
						},
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.system.user[1].uid"},
			description:    "User UIDs must be unique",
		},
		{
			name: "duplicate sysctl tunables",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
				},
				Sysctl: []model.SysctlItem{
					{
						Tunable: "net.inet.ip.random_id",
						Value:   "1",
					},
					{
						Tunable: "net.inet.ip.random_id", // Duplicate tunable
						Value:   "0",
					},
				},
			},
			expectedErrors: 1,
			expectedFields: []string{"opnsense.sysctl[1].tunable"},
			description:    "Sysctl tunable names must be unique",
		},
		{
			name: "multiple cross-field validation errors",
			config: &model.OpnSenseDocument{
				System: model.System{
					Hostname: "testhost",
					Domain:   "example.com",
					Group: []model.Group{
						{
							Name: "admin",
							Gid:  "1000",
						},
					},
					User: []model.User{
						{
							Name:      "testuser",
							UID:       "1001",
							Groupname: "nonexistent", // Invalid group reference
						},
					},
				},
				Interfaces: model.Interfaces{
					Items: map[string]model.Interface{
						"lan": {
							IPAddrv6: "track6",
							// Missing Track6Interface and Track6PrefixID
						},
					},
				},
				Dhcpd: model.Dhcpd{
					Items: map[string]model.DhcpdInterface{
						"lan": {
							Range: model.Range{
								From: "192.168.1.200",
								To:   "192.168.1.100", // Invalid range order
							},
						},
					},
				},
			},
			expectedErrors: 4,
			expectedFields: []string{
				"opnsense.system.user[0].groupname",
				"opnsense.interfaces.lan.track6-interface",
				"opnsense.interfaces.lan.track6-prefix-id",
				"opnsense.dhcpd.lan.range",
			},
			description: "Multiple cross-field validation errors should be reported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewXMLParser()
			err := parser.Validate(tt.config)

			require.Error(t, err, tt.description)

			// Check if it's an AggregatedValidationError
			var aggErr *AggregatedValidationError
			require.ErrorAs(t, err, &aggErr, "Expected AggregatedValidationError")

			assert.Len(t, aggErr.Errors, tt.expectedErrors, "Expected number of validation errors")

			// Check that all expected fields are present in errors
			actualFields := make([]string, len(aggErr.Errors))
			for i, validationErr := range aggErr.Errors {
				actualFields[i] = validationErr.Path
			}

			for _, expectedField := range tt.expectedFields {
				assert.Contains(t, actualFields, expectedField, "Expected field %s in validation errors", expectedField)
			}
		})
	}
}

// TestXMLParser_ValidateComplexScenarios tests complex validation scenarios with multiple types of errors.
func TestXMLParser_ValidateComplexScenarios(t *testing.T) {
	tests := []struct {
		name           string
		config         *model.OpnSenseDocument
		expectedErrors int
		description    string
	}{
		{
			name: "configuration with all types of validation errors",
			config: &model.OpnSenseDocument{
				System: model.System{
					// Missing hostname (required field error)
					Domain:       "example.com",
					Optimization: "invalid-opt", // Invalid enum value
					WebGUI: struct {
						Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
						SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
					}{Protocol: "ftp"}, // Invalid enum value
					Group: []model.Group{
						{
							Name: "admin",
							Gid:  "1000",
						},
						{
							Name: "admin", // Duplicate name (cross-field error)
							Gid:  "1001",
						},
					},
					User: []model.User{
						{
							Name:      "testuser",
							UID:       "1001",
							Groupname: "nonexistent", // Cross-field error
						},
					},
				},
				Filter: model.Filter{
					Rule: []model.Rule{
						{
							Type:       "invalid-type", // Invalid enum value
							IPProtocol: "inet",
							Interface:  "lan",
						},
					},
				},
			},
			expectedErrors: 7, // hostname missing, invalid optimization, invalid protocol, duplicate group name, invalid group reference, rule type, interface validation
			description:    "Configuration with mixed validation error types",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewXMLParser()
			err := parser.Validate(tt.config)

			require.Error(t, err, tt.description)

			// Check if it's an AggregatedValidationError
			var aggErr *AggregatedValidationError
			require.ErrorAs(t, err, &aggErr, "Expected AggregatedValidationError")

			assert.Len(t, aggErr.Errors, tt.expectedErrors, "Expected number of validation errors")

			// Ensure the aggregated error has meaningful error message
			assert.Contains(t, err.Error(), "validation failed", "Error message should indicate validation failure")
		})
	}
}

// TestXMLParser_ValidateValidConfiguration tests that valid configurations pass validation.
func TestXMLParser_ValidateValidConfiguration(t *testing.T) {
	validConfig := &model.OpnSenseDocument{
		System: model.System{
			Hostname:     "OPNsense",
			Domain:       "localdomain",
			Timezone:     "Etc/UTC",
			Optimization: "normal",
			WebGUI: struct {
				Protocol   string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
				SSLCertRef string `xml:"ssl-certref,omitempty" json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
			}{Protocol: "https"},
			PowerdACMode:      "hadp",
			PowerdBatteryMode: "hadp",
			PowerdNormalMode:  "hadp",
			Bogons: struct {
				Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
			}{Interval: "monthly"},
			Group: []model.Group{
				{
					Name:  "admins",
					Gid:   "1999",
					Scope: "system",
				},
			},
			User: []model.User{
				{
					Name:      "root",
					UID:       "0",
					Groupname: "admins",
					Scope:     "system",
				},
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"wan": {
					IPAddr:   "dhcp",
					IPAddrv6: "dhcp6",
				},
				"lan": {
					IPAddr:          "192.168.1.1",
					Subnet:          "24",
					IPAddrv6:        "track6",
					Subnetv6:        "64",
					Track6Interface: "wan",
					Track6PrefixID:  "0",
				},
			},
		},
		Dhcpd: model.Dhcpd{
			Items: map[string]model.DhcpdInterface{
				"lan": {
					Range: model.Range{
						From: "192.168.1.100",
						To:   "192.168.1.199",
					},
				},
			},
		},
		Filter: model.Filter{
			Rule: []model.Rule{
				{
					Type:       "pass",
					IPProtocol: "inet",
					Interface:  "lan",
					Source: model.Source{
						Network: "lan",
					},
				},
			},
		},
		Nat: model.Nat{
			Outbound: model.Outbound{
				Mode: "automatic",
			},
		},
		Sysctl: []model.SysctlItem{
			{
				Tunable: "net.inet.ip.random_id",
				Value:   "default",
				Descr:   "Randomize the ID field in IP packets",
			},
		},
	}

	parser := NewXMLParser()
	err := parser.Validate(validConfig)
	assert.NoError(t, err, "Valid configuration should not produce validation errors")
}

// TestXMLParser_ParseAndValidateIntegration tests the integration between parsing and validation.
func TestXMLParser_ParseAndValidateIntegration(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		description string
	}{
		{
			name: "valid XML with valid content",
			input: `<opnsense>
				<system>
					<hostname>testhost</hostname>
					<domain>example.com</domain>
				</system>
			</opnsense>`,
			expectError: false,
			description: "Valid XML with valid content should pass both parsing and validation",
		},
		{
			name: "valid XML with invalid content",
			input: `<opnsense>
				<system>
					<hostname></hostname>
					<domain>example.com</domain>
				</system>
			</opnsense>`,
			expectError: true,
			description: "Valid XML with invalid content should pass parsing but fail validation",
		},
		{
			name: "invalid XML syntax",
			input: `<opnsense>
				<system>
					<hostname>testhost</hostname>
					<domain>example.com</domain>
				</system>`,
			expectError: true,
			description: "Invalid XML should fail parsing before validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewXMLParser()
			reader := strings.NewReader(tt.input)

			_, err := parser.ParseAndValidate(context.Background(), reader)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}
