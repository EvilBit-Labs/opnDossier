package processor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoreProcessor_RulesAreEquivalent(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	tests := []struct {
		name     string
		rule1    model.Rule
		rule2    model.Rule
		expected bool
	}{
		{
			name: "identical rules",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Descr:      "Allow traffic",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Descr:      "Allow traffic",
				Source:     model.Source{Network: "any"},
			},
			expected: true,
		},
		{
			name: "different descriptions but same functionality",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Descr:      "Allow traffic",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Descr:      "Different description",
				Source:     model.Source{Network: "any"},
			},
			expected: true, // Should be equivalent despite different descriptions
		},
		{
			name: "same state type",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				StateType:  "keep state",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				StateType:  "keep state",
				Source:     model.Source{Network: "any"},
			},
			expected: true,
		},
		{
			name: "different state types",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				StateType:  "keep state",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				StateType:  "sloppy state",
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "state type vs empty",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				StateType:  "synproxy state",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "same direction",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Direction:  "in",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Direction:  "in",
				Source:     model.Source{Network: "any"},
			},
			expected: true,
		},
		{
			name: "different directions",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Direction:  "in",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Direction:  "out",
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "direction vs empty",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Direction:  "out",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "same protocol",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Protocol:   "tcp",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Protocol:   "tcp",
				Source:     model.Source{Network: "any"},
			},
			expected: true,
		},
		{
			name: "different protocols",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Protocol:   "udp",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Protocol:   "icmp",
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "protocol vs empty",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Protocol:   "tcp",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "any protocol handling",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Protocol:   "any",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Protocol:   "any",
				Source:     model.Source{Network: "any"},
			},
			expected: true,
		},
		{
			name: "quick flag matches",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Quick:      true,
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Quick:      true,
				Source:     model.Source{Network: "any"},
			},
			expected: true,
		},
		{
			name: "quick flag differs",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Quick:      true,
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Quick:      false,
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "same source port",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				SourcePort: "443",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				SourcePort: "443",
				Source:     model.Source{Network: "any"},
			},
			expected: true,
		},
		{
			name: "different source ports",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				SourcePort: "80",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				SourcePort: "443",
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "source port range comparison",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				SourcePort: "20:25",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				SourcePort: "20:25",
				Source:     model.Source{Network: "any"},
			},
			expected: true,
		},
		{
			name: "source port range vs single port",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				SourcePort: "50000:60000",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				SourcePort: "50000",
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "same destination port",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Port: "443"},
				Source:      model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Port: "443"},
				Source:      model.Source{Network: "any"},
			},
			expected: true,
		},
		{
			name: "different destination ports",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Port: "80"},
				Source:      model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Port: "443"},
				Source:      model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "destination port range comparison",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Port: "20:25"},
				Source:      model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Port: "20:25"},
				Source:      model.Source{Network: "any"},
			},
			expected: true,
		},
		{
			name: "destination port range vs single port",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Port: "50000:60000"},
				Source:      model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Port: "50000"},
				Source:      model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "same destination network",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Network: "192.168.1.0/24"},
				Source:      model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Network: "192.168.1.0/24"},
				Source:      model.Source{Network: "any"},
			},
			expected: true,
		},
		{
			name: "different destination networks",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Network: "192.168.1.0/24"},
				Source:      model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Network: "10.0.0.0/8"},
				Source:      model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "any destination vs specific network",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Any: model.StringPtr("1")},
				Source:      model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Destination: model.Destination{Network: "10.0.0.0/8"},
				Source:      model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "different types",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "block",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "different protocols",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet6",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "different interfaces",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"wan"},
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "different source networks",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "192.168.1.0/24"},
			},
			expected: false,
		},
		{
			name: "empty destination differs from explicit any",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Source:      model.Source{Network: "any"},
				Destination: model.Destination{},
			},
			rule2: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Source:      model.Source{Network: "any"},
				Destination: model.Destination{Any: model.StringPtr("1")},
			},
			expected: false,
		},
		{
			name: "empty destination with port vs any destination with same port",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Source:      model.Source{Network: "any"},
				Destination: model.Destination{Port: "443"},
			},
			rule2: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Source:      model.Source{Network: "any"},
				Destination: model.Destination{Any: model.StringPtr("1"), Port: "443"},
			},
			expected: false, // One has explicit network, one doesn't
		},
		{
			name: "complex rules with all fields",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"wan"},
				Descr:      "Allow web traffic",
				StateType:  "keep state",
				Direction:  "in",
				Protocol:   "tcp",
				Quick:      true,
				SourcePort: "1024:65535",
				Source:     model.Source{Network: "10.0.0.0/8"},
				Destination: model.Destination{
					Network: "192.168.1.0/24",
					Port:    "443",
				},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"wan"},
				Descr:      "Allow web traffic (duplicate)",
				StateType:  "keep state",
				Direction:  "in",
				Protocol:   "tcp",
				Quick:      true,
				SourcePort: "1024:65535",
				Source:     model.Source{Network: "10.0.0.0/8"},
				Destination: model.Destination{
					Network: "192.168.1.0/24",
					Port:    "443",
				},
			},
			expected: true, // Should be equivalent despite different descriptions
		},
		{
			name: "source IsAny pointer vs network any are not equivalent",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Any: model.StringPtr("")},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "any"},
			},
			expected: false,
		},
		{
			name: "both sources use IsAny pointer",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Any: model.StringPtr("")},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Any: model.StringPtr("1")},
			},
			expected: true, // Any compared by presence only, not value
		},
		{
			name: "different source address",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Address: "192.168.1.0/24"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Address: "10.0.0.0/8"},
			},
			expected: false,
		},
		{
			name: "different source not flag",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "lan", Not: true},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "lan"},
			},
			expected: false,
		},
		{
			name: "different source port",
			rule1: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "any", Port: "443"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Source:     model.Source{Network: "any", Port: "80"},
			},
			expected: false,
		},
		{
			name: "different destination address",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Source:      model.Source{Network: "any"},
				Destination: model.Destination{Address: "192.168.1.1"},
			},
			rule2: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Source:      model.Source{Network: "any"},
				Destination: model.Destination{Address: "10.0.0.1"},
			},
			expected: false,
		},
		{
			name: "different destination not flag",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Source:      model.Source{Network: "any"},
				Destination: model.Destination{Network: "lan", Not: true},
			},
			rule2: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"lan"},
				Source:      model.Source{Network: "any"},
				Destination: model.Destination{Network: "lan"},
			},
			expected: false,
		},
		{
			name: "different single functional field",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"wan"},
				StateType:   "keep state",
				Direction:   "in",
				Protocol:    "tcp",
				Quick:       true,
				SourcePort:  "1024:65535",
				Source:      model.Source{Network: "10.0.0.0/8"},
				Destination: model.Destination{Network: "192.168.1.0/24", Port: "443"},
			},
			rule2: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"wan"},
				StateType:   "keep state",
				Direction:   "in",
				Protocol:    "tcp",
				Quick:       true,
				SourcePort:  "1024:65535",
				Source:      model.Source{Network: "10.0.0.0/8"},
				Destination: model.Destination{Network: "192.168.1.0/24", Port: "8443"},
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

			// Use the existing parser to handle XML encoding issues
			xmlParser := cfgparser.NewXMLParser()

			config, err := xmlParser.Parse(context.Background(), file)
			if err != nil {
				t.Skipf("Skipping test due to parsing error: %v", err)
				return
			}

			// Verify the configuration has rules
			rules := config.FilterRules()
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
							"  Rule[%d]: %s %s on %s from %s",
							i,
							rule1.Type,
							rule1.IPProtocol,
							rule1.Interface,
							rule1.Source.Network,
						)
						t.Logf(
							"  Rule[%d]: %s %s on %s from %s",
							j,
							rule2.Type,
							rule2.IPProtocol,
							rule2.Interface,
							rule2.Source.Network,
						)
					}
				}
			}

			// Test dead rule detection
			deadRuleCount := 0

			for i, rule := range rules {
				if rule.Type == "block" && rule.Source.Network == "any" {
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
				if rule.Type == "pass" && rule.Source.Network == "any" && rule.Descr == "" {
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
					assert.NotEmpty(t, rule.Interface, "Rule %d should have an interface", i)

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
		// This test documents the limitations of the current model.Rule struct
		// compared to actual OPNsense configurations

		// From sample.config.2.xml, we can see these fields are missing from our model:
		// - source.any: "1" (with value)
		// - rule flags and advanced options
		// - detailed source/destination port objects beyond string values

		// Current model supports:
		// - type, ipprotocol, descr, interface
		// - statetype, direction, quick, protocol
		// - source.network, sourceport
		// - destination.any, destination.network, destination.port
		// - target
		t.Log("Current model.Rule limitations:")
		t.Log("  - Missing: rule flags and advanced options")
		t.Log("  - Limited: source.any handling is not part of equivalence check")
		t.Log("  - Limited: port semantics are compared as raw strings")
		t.Log("  - Supported comparisons: statetype, direction, protocol, quick, ports, destination network")

		// This is expected behavior for the current implementation
		// This test documents current model limitations and should always pass
		t.Log("Model limitations documented successfully")
	})
}

// TestMarkDHCPInterfaces tests the markDHCPInterfaces helper function.
func TestMarkDHCPInterfaces(t *testing.T) {
	t.Run("AllItems", func(t *testing.T) {
		// Test that all enabled DHCP interfaces in Items map are marked as used
		cfg := &model.OpnSenseDocument{
			Dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"lan":  {Enable: "1"},
					"wan":  {Enable: "1"},
					"opt0": {Enable: "1"},
					"opt1": {Enable: "1"},
				},
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

	t.Run("EmptyMap", func(t *testing.T) {
		// Test handling of nil Items map
		cfg := &model.OpnSenseDocument{
			Dhcpd: model.Dhcpd{
				Items: nil,
			},
		}

		used := make(map[string]bool)
		markDHCPInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when Items is nil")
	})

	t.Run("EmptyItemsMap", func(t *testing.T) {
		// Test handling of empty Items map
		cfg := &model.OpnSenseDocument{
			Dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{},
			},
		}

		used := make(map[string]bool)
		markDHCPInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when Items is empty")
	})

	t.Run("DisabledInterface", func(t *testing.T) {
		// Test that disabled interfaces (Enable != "1") are not marked
		// OPNsense convention: Enable="1" means enabled, anything else means disabled
		cfg := &model.OpnSenseDocument{
			Dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"lan":  {Enable: "1"},    // enabled
					"wan":  {Enable: ""},     // disabled (empty string)
					"opt0": {Enable: "1"},    // enabled
					"opt1": {},               // disabled (zero value)
					"opt2": {Enable: "true"}, // disabled (not "1")
					"opt3": {Enable: "0"},    // disabled (explicitly disabled)
				},
			},
		}

		used := make(map[string]bool)
		markDHCPInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used (enabled)")
		assert.False(t, used["wan"], "wan should NOT be marked (empty Enable)")
		assert.True(t, used["opt0"], "opt0 should be marked as used (enabled)")
		assert.False(t, used["opt1"], "opt1 should NOT be marked (zero value)")
		assert.False(t, used["opt2"], "opt2 should NOT be marked (Enable='true' is not '1')")
		assert.False(t, used["opt3"], "opt3 should NOT be marked (Enable='0' means disabled)")
	})

	t.Run("PreservesExistingEntries", func(t *testing.T) {
		// Test that existing entries in the used map are preserved
		cfg := &model.OpnSenseDocument{
			Dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"opt0": {Enable: "1"},
				},
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
		cfg := &model.OpnSenseDocument{
			Unbound: model.Unbound{
				Enable: "1",
			},
		}

		used := make(map[string]bool)
		markDNSInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used when Unbound is enabled")
	})

	t.Run("DNSMasqEnabled", func(t *testing.T) {
		// Test that when DNSMasq is enabled, "lan" is marked as used
		cfg := &model.OpnSenseDocument{
			DNSMasquerade: model.DNSMasq{
				Enable: true,
			},
		}

		used := make(map[string]bool)
		markDNSInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used when DNSMasq is enabled")
	})

	t.Run("BothDisabled", func(t *testing.T) {
		// Test that when both DNS services are disabled, no interfaces are marked
		cfg := &model.OpnSenseDocument{
			Unbound: model.Unbound{
				Enable: "", // disabled (empty string)
			},
			DNSMasquerade: model.DNSMasq{
				Enable: false, // disabled
			},
		}

		used := make(map[string]bool)
		markDNSInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when both DNS services are disabled")
	})

	t.Run("BothEnabled", func(t *testing.T) {
		// Test that when both DNS services are enabled, "lan" is still only marked once
		cfg := &model.OpnSenseDocument{
			Unbound: model.Unbound{
				Enable: "1",
			},
			DNSMasquerade: model.DNSMasq{
				Enable: true,
			},
		}

		used := make(map[string]bool)
		markDNSInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used when both DNS services are enabled")
		assert.Len(t, used, 1, "should only have one interface marked (lan)")
	})

	t.Run("PreservesExistingEntries", func(t *testing.T) {
		// Test that existing entries in the used map are preserved
		cfg := &model.OpnSenseDocument{
			Unbound: model.Unbound{
				Enable: "1",
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
		// Test various Enable values for Unbound
		// OPNsense convention: only "1" means enabled
		testCases := []struct {
			enableValue string
			shouldMark  bool
		}{
			{"1", true},
			{"true", false}, // not "1", so disabled
			{"yes", false},  // not "1", so disabled
			{"0", false},    // explicitly disabled
			{"", false},     // empty string means disabled
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("Enable=%q", tc.enableValue), func(t *testing.T) {
				cfg := &model.OpnSenseDocument{
					Unbound: model.Unbound{
						Enable: tc.enableValue,
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
		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Servers: []model.OpenVPNServer{
					{Interface: "wan"},
				},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["wan"], "wan should be marked as used from OpenVPN server")
		assert.Len(t, used, 1, "should have exactly 1 interface marked")
	})

	t.Run("MultipleServers", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Servers: []model.OpenVPNServer{
					{Interface: "wan"},
					{Interface: "opt1"},
					{Interface: "lan"},
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
		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Servers: []model.OpenVPNServer{
					{Interface: ""},
					{Interface: "wan"},
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
		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Servers: []model.OpenVPNServer{},
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
		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Clients: []model.OpenVPNClient{
					{Interface: "wan"},
				},
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["wan"], "wan should be marked as used from OpenVPN client")
		assert.Len(t, used, 1, "should have exactly 1 interface marked")
	})

	t.Run("MultipleClients", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Clients: []model.OpenVPNClient{
					{Interface: "wan"},
					{Interface: "opt2"},
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
		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Clients: []model.OpenVPNClient{
					{Interface: ""},
					{Interface: "lan"},
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
		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Servers: []model.OpenVPNServer{
					{Interface: "wan"},
				},
				Clients: []model.OpenVPNClient{
					{Interface: "opt1"},
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
		wg := &model.WireGuard{}
		wg.General.Enabled = "1"

		cfg := &model.OpnSenseDocument{
			OPNsense: model.OPNsense{
				Wireguard: wg,
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["lan"], "lan should be marked as used when WireGuard is enabled")
	})

	t.Run("WireGuardDisabled", func(t *testing.T) {
		wg := &model.WireGuard{}
		wg.General.Enabled = ""

		cfg := &model.OpnSenseDocument{
			OPNsense: model.OPNsense{
				Wireguard: wg,
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.False(t, used["lan"], "lan should NOT be marked when WireGuard is disabled")
	})

	t.Run("WireGuardEnabledVariousValues", func(t *testing.T) {
		// OPNsense convention: only "1" means enabled
		testCases := []struct {
			enableValue string
			shouldMark  bool
		}{
			{"1", true},
			{"true", false}, // not "1", so disabled
			{"yes", false},  // not "1", so disabled
			{"0", false},    // explicitly disabled
			{"", false},     // empty string means disabled
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("Enabled=%q", tc.enableValue), func(t *testing.T) {
				wg := &model.WireGuard{}
				wg.General.Enabled = tc.enableValue

				cfg := &model.OpnSenseDocument{
					OPNsense: model.OPNsense{
						Wireguard: wg,
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
		wg := &model.WireGuard{}
		wg.General.Enabled = "1"

		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Servers: []model.OpenVPNServer{
					{Interface: "wan"},
				},
			},
			OPNsense: model.OPNsense{
				Wireguard: wg,
			},
		}

		used := make(map[string]bool)
		markVPNInterfaces(cfg, used)

		assert.True(t, used["wan"], "wan should be marked from OpenVPN server")
		assert.True(t, used["lan"], "lan should be marked from WireGuard")
		assert.Len(t, used, 2, "should have exactly 2 interfaces marked")
	})
}

// TestMarkVPNInterfaces_NilConfig tests safe handling of nil VPN configurations.
func TestMarkVPNInterfaces_NilConfig(t *testing.T) {
	t.Run("NilWireGuard", func(t *testing.T) {
		// WireGuard pointer is nil
		cfg := &model.OpnSenseDocument{
			OPNsense: model.OPNsense{
				Wireguard: nil,
			},
		}

		used := make(map[string]bool)
		// Should not panic
		markVPNInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when WireGuard is nil")
	})

	t.Run("NilServersSlice", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Servers: nil,
			},
		}

		used := make(map[string]bool)
		// Should not panic
		markVPNInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when Servers is nil")
	})

	t.Run("NilClientsSlice", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Clients: nil,
			},
		}

		used := make(map[string]bool)
		// Should not panic
		markVPNInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when Clients is nil")
	})

	t.Run("AllNil", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Servers: nil,
				Clients: nil,
			},
			OPNsense: model.OPNsense{
				Wireguard: nil,
			},
		}

		used := make(map[string]bool)
		// Should not panic
		markVPNInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when all VPN configs are nil")
	})

	t.Run("PreservesExistingEntries", func(t *testing.T) {
		wg := &model.WireGuard{}
		wg.General.Enabled = "1"

		cfg := &model.OpnSenseDocument{
			OpenVPN: model.OpenVPN{
				Servers: []model.OpenVPNServer{
					{Interface: "opt1"},
				},
			},
			OPNsense: model.OPNsense{
				Wireguard: wg,
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
		cfg := &model.OpnSenseDocument{
			LoadBalancer: model.LoadBalancer{
				MonitorType: []model.MonitorType{
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
		cfg := &model.OpnSenseDocument{
			LoadBalancer: model.LoadBalancer{
				MonitorType: []model.MonitorType{
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
		cfg := &model.OpnSenseDocument{
			LoadBalancer: model.LoadBalancer{
				MonitorType: []model.MonitorType{
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
		cfg := &model.OpnSenseDocument{
			LoadBalancer: model.LoadBalancer{
				MonitorType: []model.MonitorType{},
			},
		}

		used := make(map[string]bool)
		markLoadBalancerInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when MonitorType slice is empty")
	})

	t.Run("PreservesExistingEntries", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			LoadBalancer: model.LoadBalancer{
				MonitorType: []model.MonitorType{},
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

// TestMarkLoadBalancerInterfaces_NilSlice tests safe handling of nil MonitorType slice.
func TestMarkLoadBalancerInterfaces_NilSlice(t *testing.T) {
	t.Run("NilMonitorTypeSlice", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			LoadBalancer: model.LoadBalancer{
				MonitorType: nil,
			},
		}

		used := make(map[string]bool)
		// Should not panic
		markLoadBalancerInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked when MonitorType is nil")
	})

	t.Run("DefaultLoadBalancer", func(t *testing.T) {
		// Test with default/zero-value LoadBalancer struct
		cfg := &model.OpnSenseDocument{}

		used := make(map[string]bool)
		// Should not panic
		markLoadBalancerInterfaces(cfg, used)

		assert.Empty(t, used, "no interfaces should be marked with default LoadBalancer")
	})

	t.Run("PreservesExistingEntriesWithNil", func(t *testing.T) {
		cfg := &model.OpnSenseDocument{
			LoadBalancer: model.LoadBalancer{
				MonitorType: nil,
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
		cfg := &model.OpnSenseDocument{
			Dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"lan": {Enable: "1"},
				},
			},
			Unbound: model.Unbound{Enable: "1"}, // Also marks "lan"
			LoadBalancer: model.LoadBalancer{
				MonitorType: []model.MonitorType{{Name: "ICMP"}}, // Also marks "lan"
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
		wg := &model.WireGuard{}
		wg.General.Enabled = "1"

		cfg := &model.OpnSenseDocument{
			Interfaces: model.Interfaces{
				Items: map[string]model.Interface{
					"lan":  {Enable: "1"},
					"wan":  {Enable: "1"},
					"opt0": {Enable: "1"}, // Should be detected as unused
					"opt1": {Enable: "1"},
					"opt2": {Enable: "1"},
				},
			},
			Dhcpd: model.Dhcpd{
				Items: map[string]model.DhcpdInterface{
					"opt1": {Enable: "1"}, // Marks opt1 via DHCP
				},
			},
			OpenVPN: model.OpenVPN{
				Servers: []model.OpenVPNServer{
					{Interface: "wan"}, // Marks wan via OpenVPN
				},
				Clients: []model.OpenVPNClient{
					{Interface: "opt2"}, // Marks opt2 via OpenVPN
				},
			},
			OPNsense: model.OPNsense{
				Wireguard: wg, // Marks lan via WireGuard
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
		emptyRule := model.Rule{}
		assert.True(t, processor.rulesAreEquivalent(emptyRule, emptyRule),
			"Empty rules should be equivalent to themselves")
	})

	t.Run("partial_rules", func(t *testing.T) {
		// Test with partially filled rules
		rule1 := model.Rule{Type: "pass"}
		rule2 := model.Rule{Type: "pass"}
		rule3 := model.Rule{Type: "block"}

		assert.True(t, processor.rulesAreEquivalent(rule1, rule2),
			"Rules with only type should be equivalent if types match")
		assert.False(t, processor.rulesAreEquivalent(rule1, rule3),
			"Rules with different types should not be equivalent")
	})

	t.Run("case_sensitivity", func(t *testing.T) {
		// Test case sensitivity
		rule1 := model.Rule{
			Type:       "PASS",
			IPProtocol: "INET",
			Interface:  model.InterfaceList{"LAN"},
			Source:     model.Source{Network: "ANY"},
		}
		rule2 := model.Rule{
			Type:       "pass",
			IPProtocol: "inet",
			Interface:  model.InterfaceList{"lan"},
			Source:     model.Source{Network: "any"},
		}

		// Should be case sensitive (OPNsense is case sensitive)
		assert.False(t, processor.rulesAreEquivalent(rule1, rule2),
			"Rules should be case sensitive")
	})
}

// TestCoreProcessor_DeadRuleDetection_IsAnyPath tests that dead rule detection
// works with Source.IsAny() (the *string pointer pattern from <any/> XML elements),
// not just Source.Network == "any".
func TestCoreProcessor_DeadRuleDetection_IsAnyPath(t *testing.T) {
	t.Parallel()

	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	tests := []struct {
		name           string
		rules          []model.Rule
		wantDeadRules  bool
		wantBroadRules bool
	}{
		{
			name: "block-all via IsAny pointer makes subsequent rules dead",
			rules: []model.Rule{
				{
					Type:        "block",
					Interface:   model.InterfaceList{"lan"},
					Source:      model.Source{Any: model.StringPtr("")},
					Destination: model.Destination{Any: model.StringPtr("")},
				},
				{
					Type:      "pass",
					Interface: model.InterfaceList{"lan"},
					Source:    model.Source{Network: "192.168.1.0/24"},
				},
			},
			wantDeadRules: true,
		},
		{
			name: "block with source any but specific destination is not block-all",
			rules: []model.Rule{
				{
					Type:        "block",
					Interface:   model.InterfaceList{"lan"},
					Source:      model.Source{Any: model.StringPtr("")},
					Destination: model.Destination{Network: "10.0.0.1"},
				},
				{
					Type:      "pass",
					Interface: model.InterfaceList{"lan"},
					Source:    model.Source{Network: "192.168.1.0/24"},
				},
			},
			wantDeadRules: false,
		},
		{
			name: "overly broad pass rule via IsAny pointer",
			rules: []model.Rule{
				{
					Type:      "pass",
					Interface: model.InterfaceList{"lan"},
					Source:    model.Source{Any: model.StringPtr("")},
				},
			},
			wantBroadRules: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report := NewReport(&model.OpnSenseDocument{}, Config{})

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
				if f.Type == FindingTypeSecurity && f.Title == "Overly Broad Pass Rule" {
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
