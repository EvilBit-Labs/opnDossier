package markdown

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// TestTemplateRendering verifies that both templates can render without errors.
func TestTemplateRendering(t *testing.T) {
	// Create a minimal test configuration
	testCfg := &model.OpnSenseDocument{
		System: model.System{
			Hostname: "test-firewall",
			Domain:   "test.local",
			User: []model.User{
				{
					Name:      "admin",
					UID:       "1000",
					Groupname: "admins",
					Descr:     "System Administrator",
					Scope:     "system",
				},
			},
		},
		Interfaces: model.Interfaces{
			Items: map[string]model.Interface{
				"lan": {
					If:     "em1",
					IPAddr: "10.0.0.1",
					Subnet: "24",
					Enable: "1",
				},
				"wan": {
					If:     "em0",
					IPAddr: "192.168.1.1",
					Subnet: "24",
					Enable: "1",
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
					Destination: model.Destination{
						Network: "",
					},
					Descr: "Default allow LAN to any rule",
				},
			},
		},
		Nat: model.Nat{
			Outbound: model.Outbound{
				Mode: "automatic",
			},
		},
		Dhcpd: model.Dhcpd{
			Items: map[string]model.DhcpdInterface{
				"lan": {
					Enable: "1",
					Range: model.Range{
						From: "10.0.0.100",
						To:   "10.0.0.200",
					},
				},
			},
		},
		Unbound: model.Unbound{
			Enable: "1",
		},
	}

	tests := []struct {
		name          string
		comprehensive bool
		expectedError bool
	}{
		{
			name:          "summary_template",
			comprehensive: false,
			expectedError: false,
		},
		{
			name:          "comprehensive_template",
			comprehensive: true,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create generator
			generator, err := NewMarkdownGenerator()
			require.NoError(t, err, "Failed to create markdown generator")

			// Generate markdown
			opts := Options{
				Format:        FormatMarkdown,
				Comprehensive: tt.comprehensive,
			}

			result, err := generator.Generate(context.Background(), testCfg, opts)

			if tt.expectedError {
				assert.Error(t, err, "Expected error but got none")
				return
			}

			assert.NoError(t, err, "Template rendering should not fail")
			assert.NotEmpty(t, result, "Generated markdown should not be empty")
			assert.Contains(t, result, "test-firewall", "Should contain hostname")
			assert.Contains(t, result, "test.local", "Should contain domain")
		})
	}
}

// TestTemplateRenderingWithEmptyConfig verifies templates handle empty configurations gracefully.
func TestTemplateRenderingWithEmptyConfig(t *testing.T) {
	// Create an empty configuration
	emptyCfg := &model.OpnSenseDocument{}

	tests := []struct {
		name          string
		comprehensive bool
		expectedError bool
	}{
		{
			name:          "summary_template_empty",
			comprehensive: false,
			expectedError: false, // Should handle empty config gracefully
		},
		{
			name:          "comprehensive_template_empty",
			comprehensive: true,
			expectedError: false, // Should handle empty config gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create generator
			generator, err := NewMarkdownGenerator()
			require.NoError(t, err, "Failed to create markdown generator")

			// Generate markdown
			opts := Options{
				Format:        FormatMarkdown,
				Comprehensive: tt.comprehensive,
			}

			result, err := generator.Generate(context.Background(), emptyCfg, opts)

			if tt.expectedError {
				assert.Error(t, err, "Expected error but got none")
				return
			}

			assert.NoError(t, err, "Template rendering should not fail even with empty config")
			assert.NotEmpty(t, result, "Generated markdown should not be empty even with empty config")
		})
	}
}
