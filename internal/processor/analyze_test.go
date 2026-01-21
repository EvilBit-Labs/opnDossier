package processor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/parser"
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
				Quick:      "1",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Quick:      "1",
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
				Quick:      "1",
				Source:     model.Source{Network: "any"},
			},
			rule2: model.Rule{
				Type:       "pass",
				IPProtocol: "inet",
				Interface:  model.InterfaceList{"lan"},
				Quick:      "0",
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
				Destination: model.Destination{Any: "1"},
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
			name: "empty destination equals explicit any",
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
				Destination: model.Destination{Any: "1"},
			},
			expected: true,
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
				Destination: model.Destination{Any: "1", Port: "443"},
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
				Quick:      "1",
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
				Quick:      "1",
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
			name: "different single functional field",
			rule1: model.Rule{
				Type:        "pass",
				IPProtocol:  "inet",
				Interface:   model.InterfaceList{"wan"},
				StateType:   "keep state",
				Direction:   "in",
				Protocol:    "tcp",
				Quick:       "1",
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
				Quick:       "1",
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

func TestCoreProcessor_GetDestinationString(t *testing.T) {
	processor, err := NewCoreProcessor()
	require.NoError(t, err)

	// Test that the function returns a composite key
	destAny := model.Destination{Any: "1"}
	resultAny := processor.getDestinationString(destAny)
	assert.Equal(t, "network:any|port:", resultAny, "getDestinationString should encode any destination")

	destNetwork := model.Destination{Network: "192.168.1.0/24"}
	resultNetwork := processor.getDestinationString(destNetwork)
	assert.Equal(t, "network:192.168.1.0/24|port:", resultNetwork, "getDestinationString should encode network")

	destNetworkPort := model.Destination{Network: "192.168.1.0/24", Port: "443"}
	resultNetworkPort := processor.getDestinationString(destNetworkPort)
	assert.Equal(
		t,
		"network:192.168.1.0/24|port:443",
		resultNetworkPort,
		"getDestinationString should encode network and port",
	)

	// Test empty destination is treated as "any"
	destEmpty := model.Destination{}
	resultEmpty := processor.getDestinationString(destEmpty)
	assert.Equal(t, "network:any|port:", resultEmpty, "getDestinationString should treat empty destination as any")

	// Test that empty destination and explicit Any destination produce the same result
	assert.Equal(t, resultAny, resultEmpty, "Empty destination should equal explicit Any destination")

	// Test destination with only port (no network, no any) is NOT treated as "any"
	destPortOnly := model.Destination{Port: "443"}
	resultPortOnly := processor.getDestinationString(destPortOnly)
	assert.Equal(
		t,
		"network:|port:443",
		resultPortOnly,
		"getDestinationString should not treat port-only destination as any",
	)
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
			xmlParser := parser.NewXMLParser()

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
