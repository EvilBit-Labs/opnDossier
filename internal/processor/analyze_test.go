package processor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoreProcessor_RulesAreEquivalent(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	tests := []struct {
		name     string
		rule1    common.FirewallRule
		rule2    common.FirewallRule
		expected bool
	}{
		{
			name: "identical rules",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Description: "Allow traffic",
				Source:      common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Description: "Allow traffic",
				Source:      common.RuleEndpoint{Address: "any"},
			},
			expected: true,
		},
		{
			name: "different descriptions but same functionality",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Description: "Allow traffic",
				Source:      common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Description: "Different description",
				Source:      common.RuleEndpoint{Address: "any"},
			},
			expected: true, // Should be equivalent despite different descriptions
		},
		{
			name: "same state type",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				StateType:  "keep state",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				StateType:  "keep state",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: true,
		},
		{
			name: "different state types",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				StateType:  "keep state",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				StateType:  "sloppy state",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "state type vs empty",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				StateType:  "synproxy state",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "same direction",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Direction:  "in",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Direction:  "in",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: true,
		},
		{
			name: "different directions",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Direction:  "in",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Direction:  "out",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "direction vs empty",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Direction:  "out",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "same protocol",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Protocol:   "tcp",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Protocol:   "tcp",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: true,
		},
		{
			name: "different protocols",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Protocol:   "udp",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Protocol:   "icmp",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "protocol vs empty",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Protocol:   "tcp",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "any protocol handling",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Protocol:   "any",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Protocol:   "any",
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: true,
		},
		{
			name: "quick flag matches",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Quick:      true,
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Quick:      true,
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: true,
		},
		{
			name: "quick flag differs",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Quick:      true,
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Quick:      false,
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "same source port",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any", Port: "443"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any", Port: "443"},
			},
			expected: true,
		},
		{
			name: "different source ports",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any", Port: "80"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any", Port: "443"},
			},
			expected: false,
		},
		{
			name: "source port range comparison",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any", Port: "20:25"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any", Port: "20:25"},
			},
			expected: true,
		},
		{
			name: "source port range vs single port",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any", Port: "50000:60000"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any", Port: "50000"},
			},
			expected: false,
		},
		{
			name: "same destination port",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Port: "443"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Port: "443"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			expected: true,
		},
		{
			name: "different destination ports",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Port: "80"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Port: "443"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "destination port range comparison",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Port: "20:25"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Port: "20:25"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			expected: true,
		},
		{
			name: "destination port range vs single port",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Port: "50000:60000"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Port: "50000"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "same destination network",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Address: "192.168.1.0/24"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Address: "192.168.1.0/24"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			expected: true,
		},
		{
			name: "different destination networks",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Address: "192.168.1.0/24"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Address: "10.0.0.0/8"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "any destination vs specific network",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Address: "any"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Destination: common.RuleEndpoint{Address: "10.0.0.0/8"},
				Source:      common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "different types",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "block",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "different protocols",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet6",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "different interfaces",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"wan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "different source networks",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "192.168.1.0/24"},
			},
			expected: false,
		},
		{
			name: "empty destination differs from explicit any",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "any"},
			},
			expected: false,
		},
		{
			name: "empty destination with port vs any destination with same port",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Port: "443"},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "any", Port: "443"},
			},
			expected: false, // One has explicit network, one doesn't
		},
		{
			name: "complex rules with all fields",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"wan"},
				Description: "Allow web traffic",
				StateType:   "keep state",
				Direction:   "in",
				Protocol:    "tcp",
				Quick:       true,
				Source:      common.RuleEndpoint{Address: "10.0.0.0/8", Port: "1024:65535"},
				Destination: common.RuleEndpoint{
					Address: "192.168.1.0/24",
					Port:    "443",
				},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"wan"},
				Description: "Allow web traffic (duplicate)",
				StateType:   "keep state",
				Direction:   "in",
				Protocol:    "tcp",
				Quick:       true,
				Source:      common.RuleEndpoint{Address: "10.0.0.0/8", Port: "1024:65535"},
				Destination: common.RuleEndpoint{
					Address: "192.168.1.0/24",
					Port:    "443",
				},
			},
			expected: true, // Should be equivalent despite different descriptions
		},
		{
			// In the normalized common model, both presence-based IsAny (*string pointer)
			// and Network="any" resolve to Address="any". They are therefore equivalent.
			name: "source IsAny pointer vs network any are equivalent in normalized model",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: true,
		},
		{
			// Both presence-based Any values (StringPtr("") and StringPtr("1")) normalize
			// to Address="any" in the common model, so they are equivalent.
			name: "both sources use IsAny pointer",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any"},
			},
			expected: true,
		},
		{
			name: "different source address",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "192.168.1.0/24"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "10.0.0.0/8"},
			},
			expected: false,
		},
		{
			name: "different source not flag",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "lan", Negated: true},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "lan"},
			},
			expected: false,
		},
		{
			name: "different source port",
			rule1: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any", Port: "443"},
			},
			rule2: common.FirewallRule{
				Type:       "pass",
				IPProtocol: "inet",
				Interfaces: []string{"lan"},
				Source:     common.RuleEndpoint{Address: "any", Port: "80"},
			},
			expected: false,
		},
		{
			name: "different destination address",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "192.168.1.1"},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "10.0.0.1"},
			},
			expected: false,
		},
		{
			name: "different destination not flag",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "lan", Negated: true},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"lan"},
				Source:      common.RuleEndpoint{Address: "any"},
				Destination: common.RuleEndpoint{Address: "lan"},
			},
			expected: false,
		},
		{
			name: "different single functional field",
			rule1: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"wan"},
				StateType:   "keep state",
				Direction:   "in",
				Protocol:    "tcp",
				Quick:       true,
				Source:      common.RuleEndpoint{Address: "10.0.0.0/8", Port: "1024:65535"},
				Destination: common.RuleEndpoint{Address: "192.168.1.0/24", Port: "443"},
			},
			rule2: common.FirewallRule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interfaces:  []string{"wan"},
				StateType:   "keep state",
				Direction:   "in",
				Protocol:    "tcp",
				Quick:       true,
				Source:      common.RuleEndpoint{Address: "10.0.0.0/8", Port: "1024:65535"},
				Destination: common.RuleEndpoint{Address: "192.168.1.0/24", Port: "8443"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.rulesAreEquivalent(tt.rule1, tt.rule2)
			assert.Equal(t, tt.expected, result,
				"rulesAreEquivalent(%+v, %+v) = %v, want %v", tt.rule1, tt.rule2, result, tt.expected)
		})
	}
}

// TestCoreProcessor_RealWorldConfigurations tests the implementation with actual OPNsense configuration files.
func TestCoreProcessor_RealWorldConfigurations(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	testFiles := []string{
		"../../testdata/sample.config.1.xml",
		"../../testdata/sample.config.2.xml",
		"../../testdata/sample.config.3.xml",
	}

	for _, testFile := range testFiles {
		t.Run(filepath.Base(testFile), func(t *testing.T) {
			// Open the file
			file, err := os.Open(testFile)
			if err != nil {
				t.Skipf("Skipping test due to file open error: %v", err)
				return
			}

			defer func() {
				if closeErr := file.Close(); closeErr != nil {
					t.Logf("Warning: failed to close file: %v", closeErr)
				}
			}()

			// Use the factory to parse and normalize the config into a CommonDevice
			factory := model.NewParserFactory()

			device, err := factory.CreateDevice(context.Background(), file, "", false)
			if err != nil {
				t.Skipf("Skipping test due to parsing error: %v", err)
				return
			}

			// Verify the configuration has rules
			rules := device.FirewallRules
			require.NotEmpty(t, rules, "Test file should contain firewall rules: %s", testFile)

			t.Logf("Processing %s with %d firewall rules", filepath.Base(testFile), len(rules))

			// Test duplicate rule detection
			duplicateCount := 0

			for i, rule1 := range rules {
				for j := i + 1; j < len(rules); j++ {
					rule2 := rules[j]
					if processor.rulesAreEquivalent(rule1, rule2) {
						duplicateCount++

						t.Logf("Found duplicate rules: rule[%d] and rule[%d]", i, j)
						t.Logf(
							"  Rule[%d]: %s %s on %v from %s",
							i,
							rule1.Type,
							rule1.IPProtocol,
							rule1.Interfaces,
							rule1.Source.Address,
						)
						t.Logf(
							"  Rule[%d]: %s %s on %v from %s",
							j,
							rule2.Type,
							rule2.IPProtocol,
							rule2.Interfaces,
							rule2.Source.Address,
						)
					}
				}
			}

			// Test dead rule detection
			deadRuleCount := 0

			for i, rule := range rules {
				if rule.Type == "block" && rule.Source.Address == "any" {
					// Check if there are rules after this block-all rule
					if i < len(rules)-1 {
						deadRuleCount++

						t.Logf("Found potential dead rules after block-all rule at position %d", i+1)
					}
				}
			}

			// Test security analysis
			securityIssues := 0

			for i, rule := range rules {
				if rule.Type == "pass" && rule.Source.Address == "any" && rule.Description == "" {
					securityIssues++

					t.Logf("Found overly broad pass rule at position %d without description", i+1)
				}
			}

			t.Logf("Analysis results for %s:", filepath.Base(testFile))
			t.Logf("  - Total rules: %d", len(rules))
			t.Logf("  - Duplicate rules found: %d", duplicateCount)
			t.Logf("  - Dead rules found: %d", deadRuleCount)
			t.Logf("  - Security issues found: %d", securityIssues)

			// Verify that our implementation can handle all rule types in the test files
			for i, rule := range rules {
				t.Run(fmt.Sprintf("rule_%d_validation", i), func(t *testing.T) {
					// Test that all required fields are present
					assert.NotEmpty(t, rule.Type, "Rule %d should have a type", i)
					assert.NotEmpty(t, rule.IPProtocol, "Rule %d should have an IP protocol", i)
					assert.NotEmpty(t, rule.Interfaces, "Rule %d should have an interface", i)

					// Test that the rule can be compared with itself
					assert.True(t, processor.rulesAreEquivalent(rule, rule),
						"Rule %d should be equivalent to itself", i)
				})
			}
		})
	}
}

// TestCoreProcessor_ModelLimitations documents the current limitations of the model.
func TestCoreProcessor_ModelLimitations(t *testing.T) {
	t.Run("missing_fields_documentation", func(t *testing.T) {
		// This test documents the limitations of the current common.FirewallRule struct
		// compared to actual OPNsense configurations.

		// The common.FirewallRule (normalized model) supports:
		// - type, ipProtocol, description, interfaces
		// - stateType, direction, quick, protocol
		// - source.address, source.port, source.negated
		// - destination.address, destination.port, destination.negated
		// - target, gateway, log, disabled
		t.Log("Current common.FirewallRule supported comparisons:")
		t.Log("  - stateType, direction, protocol, quick")
		t.Log("  - source.address (normalized from any/network/address)")
		t.Log("  - source.port, source.negated")
		t.Log("  - destination.address, destination.port, destination.negated")
		t.Log("  - Port semantics are compared as raw strings")

		// This is expected behavior for the current implementation
		// This test documents current model limitations and should always pass
		t.Log("Model limitations documented successfully")
	})
}

// TestMarkDHCPInterfaces tests the markDHCPInterfaces helper function.
func TestMarkDHCPInterfaces(t *testing.T) {
	t.Run("AllItems", func(t *testing.T) {
		// Test that all enabled DHCP scopes are marked as used
		cfg := &common.CommonDevice{
			DHCP: []common.DHCPScope{
				{Interface: "lan", Enabled: true},
				{Interface: "wan", Enabled: true},
				{Interface: "opt0", Enabled: true},
				{Interface: "opt1", Enabled: true},
			},
		}

		used := make(map[string]bool)
		markDHCPInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used")
		assert.True(t, used["wan"], "wan should be marked as used")
		assert.True(t, used["opt0"], "opt0 should be marked as used")
		assert.True(t, used["opt1"], "opt1 should be marked as used")
		assert.Len(t, used, 4, "should have exactly 4 interfaces marked")
	})

	t.Run("EmptySlice", func(t *testing.T) {
		// Test handling of nil DHCP slice
		cfg := &common.CommonDevice{
			DHCP: nil,
		}

		used := make(map[string]bool)
		markDHCPInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when DHCP is nil")
	})

	t.Run("EmptyItemsSlice", func(t *testing.T) {
		// Test handling of empty DHCP slice
		cfg := &common.CommonDevice{
			DHCP: []common.DHCPScope{},
		}

		used := make(map[string]bool)
		markDHCPInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when DHCP slice is empty")
	})

	t.Run("DisabledInterface", func(t *testing.T) {
		// Test that disabled DHCP scopes (Enabled: false) are not marked
		cfg := &common.CommonDevice{
			DHCP: []common.DHCPScope{
				{Interface: "lan", Enabled: true},  // enabled
				{Interface: "wan", Enabled: false}, // disabled
				{Interface: "opt0", Enabled: true}, // enabled
				{Interface: "opt1"},                // disabled (zero value)
			},
		}

		used := make(map[string]bool)
		markDHCPInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used (enabled)")
		assert.False(t, used["wan"], "wan should NOT be marked (Enabled: false)")
		assert.True(t, used["opt0"], "opt0 should be marked as used (enabled)")
		assert.False(t, used["opt1"], "opt1 should NOT be marked (zero value, Enabled: false)")
	})

	t.Run("PreservesExistingEntries", func(t *testing.T) {
		// Test that existing entries in the used map are preserved
		cfg := &common.CommonDevice{
			DHCP: []common.DHCPScope{
				{Interface: "opt0", Enabled: true},
			},
		}

		used := map[string]bool{
			"lan": true,
			"wan": true,
		}
		markDHCPInterfaces(cfg, used)

		assert.True(t, used["lan"], "pre-existing lan entry should be preserved")
		assert.True(t, used["wan"], "pre-existing wan entry should be preserved")
		assert.True(t, used["opt0"], "opt0 should be marked as used")
		assert.Len(t, used, 3, "should have 3 interfaces marked")
	})
}

// TestMarkDNSInterfaces tests the markDNSInterfaces helper function.
func TestMarkDNSInterfaces(t *testing.T) {
	t.Run("UnboundEnabled", func(t *testing.T) {
		// Test that when Unbound DNS is enabled, "lan" is marked as used
		cfg := &common.CommonDevice{
			DNS: common.DNSConfig{
				Unbound: common.UnboundConfig{Enabled: true},
			},
		}

		used := make(map[string]bool)
		markDNSInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used when Unbound is enabled")
	})

	t.Run("DNSMasqEnabled", func(t *testing.T) {
		// Test that when DNSMasq is enabled, "lan" is marked as used
		cfg := &common.CommonDevice{
			DNS: common.DNSConfig{
				DNSMasq: common.DNSMasqConfig{Enabled: true},
			},
		}

		used := make(map[string]bool)
		markDNSInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used when DNSMasq is enabled")
	})

	t.Run("BothDisabled", func(t *testing.T) {
		// Test that when both DNS services are disabled, no interfaces are marked
		cfg := &common.CommonDevice{
			DNS: common.DNSConfig{
				Unbound: common.UnboundConfig{Enabled: false},
				DNSMasq: common.DNSMasqConfig{Enabled: false},
			},
		}

		used := make(map[string]bool)
		markDNSInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when both DNS services are disabled")
	})

	t.Run("BothEnabled", func(t *testing.T) {
		// Test that when both DNS services are enabled, "lan" is still only marked once
		cfg := &common.CommonDevice{
			DNS: common.DNSConfig{
				Unbound: common.UnboundConfig{Enabled: true},
				DNSMasq: common.DNSMasqConfig{Enabled: true},
			},
		}

		used := make(map[string]bool)
		markDNSInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used when both DNS services are enabled")
		assert.Len(t, used, 1, "should only have one interface marked (lan)")
	})

	t.Run("PreservesExistingEntries", func(t *testing.T) {
		// Test that existing entries in the used map are preserved
		cfg := &common.CommonDevice{
			DNS: common.DNSConfig{
				Unbound: common.UnboundConfig{Enabled: true},
			},
		}

		used := map[string]bool{
			"wan":  true,
			"opt0": true,
		}
		markDNSInterfaces(cfg, used)

		assert.True(t, used["wan"], "pre-existing wan entry should be preserved")
		assert.True(t, used["opt0"], "pre-existing opt0 entry should be preserved")
		assert.True(t, used["lan"], "lan should be marked as used")
		assert.Len(t, used, 3, "should have 3 interfaces marked")
	})

	t.Run("UnboundEnabledVariousValues", func(t *testing.T) {
		// In the normalized model, Enabled is a bool. Test true and false cases.
		testCases := []struct {
			enabled    bool
			shouldMark bool
		}{
			{true, true},
			{false, false},
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("Enabled=%v", tc.enabled), func(t *testing.T) {
				cfg := &common.CommonDevice{
					DNS: common.DNSConfig{
						Unbound: common.UnboundConfig{Enabled: tc.enabled},
					},
				}

				used := make(map[string]bool)
				markDNSInterfaces(cfg, used)

				if tc.shouldMark {
					assert.True(t, used["lan"], "lan should be marked as used")
				} else {
					assert.False(t, used["lan"], "lan should NOT be marked as used")
				}
			})
		}
	})
}

// TestMarkVPNInterfaces_OpenVPNServers tests that OpenVPN server interfaces are marked as used.
func TestMarkVPNInterfaces_OpenVPNServers(t *testing.T) {
	t.Run("SingleServer", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Servers: []common.OpenVPNServer{
						{Interface: "wan"},
					},
				},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["wan"], "wan should be marked as used from OpenVPN server")
		assert.Len(t, used, 1, "should have exactly 1 interface marked")
	})

	t.Run("MultipleServers", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Servers: []common.OpenVPNServer{
						{Interface: "wan"},
						{Interface: "opt1"},
						{Interface: "lan"},
					},
				},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["wan"], "wan should be marked as used")
		assert.True(t, used["opt1"], "opt1 should be marked as used")
		assert.True(t, used["lan"], "lan should be marked as used")
		assert.Len(t, used, 3, "should have exactly 3 interfaces marked")
	})

	t.Run("EmptyInterface", func(t *testing.T) {
		// Servers with empty interface field should not mark anything
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Servers: []common.OpenVPNServer{
						{Interface: ""},
						{Interface: "wan"},
					},
				},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["wan"], "wan should be marked as used")
		assert.False(t, used[""], "empty interface should not be marked")
		assert.Len(t, used, 1, "should have exactly 1 interface marked")
	})

	t.Run("NoServers", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Servers: []common.OpenVPNServer{},
				},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when no servers exist")
	})
}

// TestMarkVPNInterfaces_OpenVPNClients tests that OpenVPN client interfaces are marked as used.
func TestMarkVPNInterfaces_OpenVPNClients(t *testing.T) {
	t.Run("SingleClient", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Clients: []common.OpenVPNClient{
						{Interface: "wan"},
					},
				},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["wan"], "wan should be marked as used from OpenVPN client")
		assert.Len(t, used, 1, "should have exactly 1 interface marked")
	})

	t.Run("MultipleClients", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Clients: []common.OpenVPNClient{
						{Interface: "wan"},
						{Interface: "opt2"},
					},
				},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["wan"], "wan should be marked as used")
		assert.True(t, used["opt2"], "opt2 should be marked as used")
		assert.Len(t, used, 2, "should have exactly 2 interfaces marked")
	})

	t.Run("EmptyInterface", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Clients: []common.OpenVPNClient{
						{Interface: ""},
						{Interface: "lan"},
					},
				},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used")
		assert.False(t, used[""], "empty interface should not be marked")
		assert.Len(t, used, 1, "should have exactly 1 interface marked")
	})

	t.Run("MixedServersAndClients", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Servers: []common.OpenVPNServer{
						{Interface: "wan"},
					},
					Clients: []common.OpenVPNClient{
						{Interface: "opt1"},
					},
				},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["wan"], "wan should be marked as used from server")
		assert.True(t, used["opt1"], "opt1 should be marked as used from client")
		assert.Len(t, used, 2, "should have exactly 2 interfaces marked")
	})
}

// TestMarkVPNInterfaces_WireGuard tests that WireGuard interfaces are marked as used.
func TestMarkVPNInterfaces_WireGuard(t *testing.T) {
	t.Run("WireGuardEnabled", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				WireGuard: common.WireGuardConfig{Enabled: true},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used when WireGuard is enabled")
	})

	t.Run("WireGuardDisabled", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				WireGuard: common.WireGuardConfig{Enabled: false},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.False(t, used["lan"], "lan should NOT be marked when WireGuard is disabled")
	})

	t.Run("WireGuardEnabledVariousValues", func(t *testing.T) {
		// In the normalized model, Enabled is a bool. Test true and false cases.
		testCases := []struct {
			enabled    bool
			shouldMark bool
		}{
			{true, true},
			{false, false},
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("Enabled=%v", tc.enabled), func(t *testing.T) {
				cfg := &common.CommonDevice{
					VPN: common.VPN{
						WireGuard: common.WireGuardConfig{Enabled: tc.enabled},
					},
				}

				used := make(map[string]bool)
				markVPNInterfaces(cfg, used)

				if tc.shouldMark {
					assert.True(t, used["lan"], "lan should be marked as used")
				} else {
					assert.False(t, used["lan"], "lan should NOT be marked as used")
				}
			})
		}
	})

	t.Run("WireGuardWithOpenVPN", func(t *testing.T) {
		// Test that WireGuard and OpenVPN interfaces are all marked
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Servers: []common.OpenVPNServer{
						{Interface: "wan"},
					},
				},
				WireGuard: common.WireGuardConfig{Enabled: true},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["wan"], "wan should be marked from OpenVPN server")
		assert.True(t, used["lan"], "lan should be marked from WireGuard")
		assert.Len(t, used, 2, "should have exactly 2 interfaces marked")
	})
}

// TestMarkVPNInterfaces_NilConfig tests safe handling of nil/empty VPN configurations.
func TestMarkVPNInterfaces_NilConfig(t *testing.T) {
	t.Run("ZeroValueWireGuard", func(t *testing.T) {
		// WireGuard with zero-value config has Enabled: false
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				WireGuard: common.WireGuardConfig{},
			},
		}

		used := make(map[string]bool)
		// Should not panic
		markVPNInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when WireGuard is zero-value (disabled)")
	})

	t.Run("NilServersSlice", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Servers: nil,
				},
			},
		}

		used := make(map[string]bool)
		// Should not panic
		markVPNInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when Servers is nil")
	})

	t.Run("NilClientsSlice", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Clients: nil,
				},
			},
		}

		used := make(map[string]bool)
		// Should not panic
		markVPNInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when Clients is nil")
	})

	t.Run("AllNil", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Servers: nil,
					Clients: nil,
				},
				WireGuard: common.WireGuardConfig{},
			},
		}

		used := make(map[string]bool)
		// Should not panic
		markVPNInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when all VPN configs are nil/zero")
	})

	t.Run("PreservesExistingEntries", func(t *testing.T) {
		cfg := &common.CommonDevice{
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Servers: []common.OpenVPNServer{
						{Interface: "opt1"},
					},
				},
				WireGuard: common.WireGuardConfig{Enabled: true},
			},
		}

		used := map[string]bool{
			"wan":  true,
			"opt0": true,
		}
		markVPNInterfaces(cfg, used)

		assert.True(t, used["wan"], "pre-existing wan entry should be preserved")
		assert.True(t, used["opt0"], "pre-existing opt0 entry should be preserved")
		assert.True(t, used["opt1"], "opt1 should be marked from OpenVPN server")
		assert.True(t, used["lan"], "lan should be marked from WireGuard")
		assert.Len(t, used, 4, "should have 4 interfaces marked")
	})
}

// TestMarkLoadBalancerInterfaces_WithMonitors tests that load balancer interfaces are marked as used
// when monitor types are configured.
func TestMarkLoadBalancerInterfaces_WithMonitors(t *testing.T) {
	t.Run("SingleMonitor", func(t *testing.T) {
		cfg := &common.CommonDevice{
			LoadBalancer: common.LoadBalancerConfig{
				MonitorTypes: []common.MonitorType{
					{Name: "ICMP", Type: "icmp"},
				},
			},
		}

		used := make(map[string]bool)
		markLoadBalancerInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used when load balancer monitors are configured")
		assert.Len(t, used, 1, "should have exactly 1 interface marked")
	})

	t.Run("MultipleMonitors", func(t *testing.T) {
		cfg := &common.CommonDevice{
			LoadBalancer: common.LoadBalancerConfig{
				MonitorTypes: []common.MonitorType{
					{Name: "ICMP", Type: "icmp"},
					{Name: "HTTP", Type: "http"},
					{Name: "TCP", Type: "tcp"},
				},
			},
		}

		used := make(map[string]bool)
		markLoadBalancerInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used when multiple monitors are configured")
		assert.Len(t, used, 1, "should have exactly 1 interface marked (lan only)")
	})

	t.Run("PreservesExistingEntries", func(t *testing.T) {
		cfg := &common.CommonDevice{
			LoadBalancer: common.LoadBalancerConfig{
				MonitorTypes: []common.MonitorType{
					{Name: "ICMP", Type: "icmp"},
				},
			},
		}

		used := map[string]bool{
			"wan":  true,
			"opt0": true,
		}
		markLoadBalancerInterfaces(cfg, used)

		assert.True(t, used["wan"], "pre-existing wan entry should be preserved")
		assert.True(t, used["opt0"], "pre-existing opt0 entry should be preserved")
		assert.True(t, used["lan"], "lan should be marked as used")
		assert.Len(t, used, 3, "should have 3 interfaces marked")
	})
}

// TestMarkLoadBalancerInterfaces_EmptyMonitors tests that no interfaces are marked
// when no load balancer monitors are configured.
func TestMarkLoadBalancerInterfaces_EmptyMonitors(t *testing.T) {
	t.Run("EmptySlice", func(t *testing.T) {
		cfg := &common.CommonDevice{
			LoadBalancer: common.LoadBalancerConfig{
				MonitorTypes: []common.MonitorType{},
			},
		}

		used := make(map[string]bool)
		markLoadBalancerInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when MonitorTypes slice is empty")
	})

	t.Run("PreservesExistingEntries", func(t *testing.T) {
		cfg := &common.CommonDevice{
			LoadBalancer: common.LoadBalancerConfig{
				MonitorTypes: []common.MonitorType{},
			},
		}

		used := map[string]bool{
			"wan": true,
			"lan": true,
		}
		markLoadBalancerInterfaces(cfg, used)

		assert.True(t, used["wan"], "pre-existing wan entry should be preserved")
		assert.True(t, used["lan"], "pre-existing lan entry should be preserved")
		assert.Len(t, used, 2, "should still have 2 interfaces marked")
	})
}

// TestMarkLoadBalancerInterfaces_NilSlice tests safe handling of nil MonitorTypes slice.
func TestMarkLoadBalancerInterfaces_NilSlice(t *testing.T) {
	t.Run("NilMonitorTypeSlice", func(t *testing.T) {
		cfg := &common.CommonDevice{
			LoadBalancer: common.LoadBalancerConfig{
				MonitorTypes: nil,
			},
		}

		used := make(map[string]bool)
		// Should not panic
		markLoadBalancerInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when MonitorTypes is nil")
	})

	t.Run("DefaultLoadBalancer", func(t *testing.T) {
		// Test with default/zero-value LoadBalancerConfig struct
		cfg := &common.CommonDevice{}

		used := make(map[string]bool)
		// Should not panic
		markLoadBalancerInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked with default LoadBalancer")
	})

	t.Run("PreservesExistingEntriesWithNil", func(t *testing.T) {
		cfg := &common.CommonDevice{
			LoadBalancer: common.LoadBalancerConfig{
				MonitorTypes: nil,
			},
		}

		used := map[string]bool{
			"wan":  true,
			"opt1": true,
		}
		markLoadBalancerInterfaces(cfg, used)

		assert.True(t, used["wan"], "pre-existing wan entry should be preserved")
		assert.True(t, used["opt1"], "pre-existing opt1 entry should be preserved")
		assert.Len(t, used, 2, "should still have 2 interfaces marked")
	})
}

// TestServiceDetection_Integration tests that all service detection helpers work together
// in the analyzeUnusedInterfaces function.
func TestServiceDetection_Integration(t *testing.T) {
	t.Run("MultipleServicesMarkingSameInterface", func(t *testing.T) {
		// Test that multiple services can mark the same interface (idempotent)
		cfg := &common.CommonDevice{
			DHCP: []common.DHCPScope{
				{Interface: "lan", Enabled: true},
			},
			DNS: common.DNSConfig{
				Unbound: common.UnboundConfig{Enabled: true}, // Also marks "lan"
			},
			LoadBalancer: common.LoadBalancerConfig{
				MonitorTypes: []common.MonitorType{{Name: "ICMP"}}, // Also marks "lan"
			},
		}

		used := make(map[string]bool)
		markDHCPInterfaces(cfg, used)
		markDNSInterfaces(cfg, used)
		markLoadBalancerInterfaces(cfg, used)

		assert.True(t, used["lan"])
		assert.Len(t, used, 1, "should only have one entry despite multiple services marking 'lan'")
	})

	t.Run("AllServiceTypesDetection", func(t *testing.T) {
		// Test that interfaces from all service types are correctly accumulated
		cfg := &common.CommonDevice{
			Interfaces: []common.Interface{
				{Name: "lan", Enabled: true},
				{Name: "wan", Enabled: true},
				{Name: "opt0", Enabled: true}, // Should be detected as unused
				{Name: "opt1", Enabled: true},
				{Name: "opt2", Enabled: true},
			},
			DHCP: []common.DHCPScope{
				{Interface: "opt1", Enabled: true}, // Marks opt1 via DHCP
			},
			VPN: common.VPN{
				OpenVPN: common.OpenVPNConfig{
					Servers: []common.OpenVPNServer{
						{Interface: "wan"}, // Marks wan via OpenVPN
					},
					Clients: []common.OpenVPNClient{
						{Interface: "opt2"}, // Marks opt2 via OpenVPN
					},
				},
				WireGuard: common.WireGuardConfig{Enabled: true}, // Marks lan via WireGuard
			},
		}

		used := make(map[string]bool)
		markDHCPInterfaces(cfg, used)
		markDNSInterfaces(cfg, used)
		markVPNInterfaces(cfg, used)
		markLoadBalancerInterfaces(cfg, used)

		// Verify all services marked their interfaces
		assert.True(t, used["lan"], "lan should be marked from WireGuard")
		assert.True(t, used["wan"], "wan should be marked from OpenVPN server")
		assert.True(t, used["opt1"], "opt1 should be marked from DHCP")
		assert.True(t, used["opt2"], "opt2 should be marked from OpenVPN client")
		assert.False(t, used["opt0"], "opt0 should NOT be marked (unused)")
	})
}

// TestCoreProcessor_EdgeCases tests edge cases and boundary conditions.
func TestCoreProcessor_EdgeCases(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	t.Run("empty_rules", func(t *testing.T) {
		// Test with empty rules
		emptyRule := common.FirewallRule{}
		assert.True(t, processor.rulesAreEquivalent(emptyRule, emptyRule),
			"Empty rules should be equivalent to themselves")
	})

	t.Run("partial_rules", func(t *testing.T) {
		// Test with partially filled rules
		rule1 := common.FirewallRule{Type: "pass"}
		rule2 := common.FirewallRule{Type: "pass"}
		rule3 := common.FirewallRule{Type: "block"}

		assert.True(t, processor.rulesAreEquivalent(rule1, rule2),
			"Rules with only type should be equivalent if types match")
		assert.False(t, processor.rulesAreEquivalent(rule1, rule3),
			"Rules with different types should not be equivalent")
	})

	t.Run("case_sensitivity", func(t *testing.T) {
		// Test case sensitivity
		rule1 := common.FirewallRule{
			Type:       "PASS",
			IPProtocol: "INET",
			Interfaces: []string{"LAN"},
			Source:     common.RuleEndpoint{Address: "ANY"},
		}
		rule2 := common.FirewallRule{
			Type:       "pass",
			IPProtocol: "inet",
			Interfaces: []string{"lan"},
			Source:     common.RuleEndpoint{Address: "any"},
		}

		// Should be case sensitive (OPNsense is case sensitive)
		assert.False(t, processor.rulesAreEquivalent(rule1, rule2),
			"Rules should be case sensitive")
	})
}

// TestCoreProcessor_DeadRuleDetection_IsAnyPath tests that dead rule detection
// works with Source.Address == "any" (the normalized representation of both
// the old IsAny() *string pointer pattern from <any/> XML elements and
// the Network="any" value-based pattern).
func TestCoreProcessor_DeadRuleDetection_IsAnyPath(t *testing.T) {
	t.Parallel()

	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	tests := []struct {
		name           string
		rules          []common.FirewallRule
		wantDeadRules  bool
		wantBroadRules bool
	}{
		{
			name: "block-all via IsAny pointer makes subsequent rules dead",
			rules: []common.FirewallRule{
				{
					Type:        "block",
					Interfaces:  []string{"lan"},
					Source:      common.RuleEndpoint{Address: "any"},
					Destination: common.RuleEndpoint{Address: "any"},
				},
				{
					Type:       "pass",
					Interfaces: []string{"lan"},
					Source:     common.RuleEndpoint{Address: "192.168.1.0/24"},
				},
			},
			wantDeadRules: true,
		},
		{
			name: "block with source any but specific destination is not block-all",
			rules: []common.FirewallRule{
				{
					Type:        "block",
					Interfaces:  []string{"lan"},
					Source:      common.RuleEndpoint{Address: "any"},
					Destination: common.RuleEndpoint{Address: "10.0.0.1"},
				},
				{
					Type:       "pass",
					Interfaces: []string{"lan"},
					Source:     common.RuleEndpoint{Address: "192.168.1.0/24"},
				},
			},
			wantDeadRules: false,
		},
		{
			name: "overly broad pass rule via IsAny pointer",
			rules: []common.FirewallRule{
				{
					Type:       "pass",
					Interfaces: []string{"lan"},
					Source:     common.RuleEndpoint{Address: "any"},
				},
			},
			wantBroadRules: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report := NewReport(&common.CommonDevice{}, Config{})

			processor.analyzeInterfaceRules("lan", tt.rules, report)

			// Collect all findings across severity levels
			var allFindings []Finding
			allFindings = append(allFindings, report.Findings.Critical...)
			allFindings = append(allFindings, report.Findings.High...)
			allFindings = append(allFindings, report.Findings.Medium...)
			allFindings = append(allFindings, report.Findings.Low...)
			allFindings = append(allFindings, report.Findings.Info...)

			hasDeadRule := false
			hasBroadRule := false
			for _, f := range allFindings {
				if f.Type == "dead-rule" {
					hasDeadRule = true
				}
				if f.Type == constants.FindingTypeSecurity && f.Title == "Overly Broad Pass Rule" {
					hasBroadRule = true
				}
			}

			if tt.wantDeadRules {
				assert.True(t, hasDeadRule, "expected dead-rule finding")
			} else {
				assert.False(t, hasDeadRule, "unexpected dead-rule finding")
			}

			if tt.wantBroadRules {
				assert.True(t, hasBroadRule, "expected overly broad pass rule finding")
			}
		})
	}
}
