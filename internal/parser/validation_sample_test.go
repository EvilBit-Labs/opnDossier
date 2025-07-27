package parser

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/opnFocus/internal/validator"
)

// TestXMLParser_SampleConfig2XMLValidation tests that sample.config.2.xml produces no validation errors.
// This is part of the requirement to extend existing tests for opt0/optN interface support.
func TestXMLParser_SampleConfig2XMLValidation(t *testing.T) {
	// Path to the sample config file
	sampleFile := "../../testdata/sample.config.2.xml"

	// Check if file exists
	if _, err := os.Stat(sampleFile); os.IsNotExist(err) {
		t.Skip("sample.config.2.xml not found in testdata directory")
	}

	// Parse the XML file
	xmlParser := NewXMLParser()
	file, err := os.Open(sampleFile)
	require.NoError(t, err, "Failed to open sample.config.2.xml")
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Logf("Warning: failed to close file: %v", closeErr)
		}
	}()

	config, err := xmlParser.Parse(context.Background(), file)
	require.NoError(t, err, "Failed to parse sample.config.2.xml")
	require.NotNil(t, config, "Parsed config should not be nil")

	// Validate the configuration
	errors := validator.ValidateOpnsense(config)

	// Assert that there are no validation errors
	if len(errors) > 0 {
		t.Logf("Found %d validation errors in sample.config.2.xml:", len(errors))
		for i, err := range errors {
			t.Logf("  %d: %s", i+1, err.Error())
		}
	}
	assert.Len(t, errors, 0, "sample.config.2.xml should produce zero validation errors")

	// Log some information about the parsed configuration for verification
	t.Logf("Configuration loaded successfully:")
	t.Logf("  - Hostname: %s", config.System.Hostname)
	t.Logf("  - Domain: %s", config.System.Domain)
	t.Logf("  - Interfaces: %v", config.Interfaces.Names())
	t.Logf("  - Filter rules: %d", len(config.Filter.Rule))
	t.Logf("  - Sysctl items: %d", len(config.Sysctl))

	// Verify that opt interfaces are present and properly parsed
	interfaceNames := config.Interfaces.Names()
	expectedOptInterfaces := []string{"opt0", "opt1", "opt2"}
	for _, expected := range expectedOptInterfaces {
		assert.Contains(t, interfaceNames, expected, "Expected opt interface '%s' should be present", expected)
		if iface, ok := config.Interfaces.Get(expected); ok {
			t.Logf("  - %s: enabled=%s, if=%s", expected, iface.Enable, iface.If)
		}
	}
}
