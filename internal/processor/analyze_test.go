package processor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRulesEquivalent(t *testing.T) {
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
			expected: true,
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
			expected: false,
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
			expected: true,
		},
		{
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
			result := analysis.RulesEquivalent(tt.rule1, tt.rule2)
			assert.Equal(t, tt.expected, result,
				"RulesEquivalent(%+v, %+v) = %v, want %v", tt.rule1, tt.rule2, result, tt.expected)
		})
	}
}

// TestCoreProcessor_RealWorldConfigurations tests the implementation with actual OPNsense configuration files.
func TestCoreProcessor_RealWorldConfigurations(t *testing.T) {
	testFiles := []string{
		"../../testdata/sample.config.1.xml",
		"../../testdata/sample.config.2.xml",
		"../../testdata/sample.config.3.xml",
	}

	for _, testFile := range testFiles {
		t.Run(filepath.Base(testFile), func(t *testing.T) {
			const anyAddress = "any"

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
			factory := parser.NewFactory(cfgparser.NewXMLParser())

			device, _, err := factory.CreateDevice(context.Background(), file, "", false)
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
					if analysis.RulesEquivalent(rule1, rule2) {
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
				if rule.Type == "block" && rule.Source.Address == anyAddress {
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
				if rule.Type == "pass" && rule.Source.Address == anyAddress && rule.Description == "" {
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
					assert.True(t, analysis.RulesEquivalent(rule, rule),
						"Rule %d should be equivalent to itself", i)
				})
			}
		})
	}
}

// TestCoreProcessor_ModelLimitations documents the current limitations of the model.
func TestCoreProcessor_ModelLimitations(t *testing.T) {
	t.Run("missing_fields_documentation", func(t *testing.T) {
		t.Log("Current common.FirewallRule supported comparisons:")
		t.Log("  - stateType, direction, protocol, quick")
		t.Log("  - source.address (normalized from any/network/address)")
		t.Log("  - source.port, source.negated")
		t.Log("  - destination.address, destination.port, destination.negated")
		t.Log("  - Port semantics are compared as raw strings")
		t.Log("Model limitations documented successfully")
	})
}

// TestCoreProcessor_EdgeCases tests edge cases and boundary conditions.
func TestCoreProcessor_EdgeCases(t *testing.T) {
	t.Run("empty_rules", func(t *testing.T) {
		emptyRule := common.FirewallRule{}
		assert.True(t, analysis.RulesEquivalent(emptyRule, emptyRule),
			"Empty rules should be equivalent to themselves")
	})

	t.Run("partial_rules", func(t *testing.T) {
		rule1 := common.FirewallRule{Type: "pass"}
		rule2 := common.FirewallRule{Type: "pass"}
		rule3 := common.FirewallRule{Type: "block"}

		assert.True(t, analysis.RulesEquivalent(rule1, rule2),
			"Rules with only type should be equivalent if types match")
		assert.False(t, analysis.RulesEquivalent(rule1, rule3),
			"Rules with different types should not be equivalent")
	})

	t.Run("case_sensitivity", func(t *testing.T) {
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
		assert.False(t, analysis.RulesEquivalent(rule1, rule2),
			"Rules should be case sensitive")
	})
}

// TestCoreProcessor_DeadRuleDetection_IsAnyPath tests that dead rule detection
// works with Source.Address == "any" (the normalized representation of both
// the old IsAny() *string pointer pattern from <any/> XML elements and
// the Network="any" value-based pattern).
func TestCoreProcessor_DeadRuleDetection_IsAnyPath(t *testing.T) {
	t.Parallel()

	processor, err := NewCoreProcessor(nil)
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

			cfg := &common.CommonDevice{
				FirewallRules: tt.rules,
			}
			report := NewReport(cfg, Config{})

			// Test dead rule detection via shared analysis
			processor.analyzeDeadRules(cfg, report)

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
