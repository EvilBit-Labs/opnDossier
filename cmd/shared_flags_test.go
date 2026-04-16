package cmd

import (
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddSharedContentFlagsRegistersFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	addSharedContentFlags(cmd)

	flags := cmd.Flags()
	// These flags should exist
	require.NotNil(t, flags.Lookup("section"))
	require.NotNil(t, flags.Lookup("wrap"))
	require.NotNil(t, flags.Lookup("no-wrap"))
	require.NotNil(t, flags.Lookup("include-tunables"))
	require.NotNil(t, flags.Lookup("comprehensive"))

	// These template-related flags should NOT exist
	assert.Nil(t, flags.Lookup("legacy"))
	assert.Nil(t, flags.Lookup("custom-template"))
	assert.Nil(t, flags.Lookup("template-cache-size"))
	assert.Nil(t, flags.Lookup("use-template"))
	assert.Nil(t, flags.Lookup("engine"))

	// Redact flag lives in addSharedRedactFlag, not here
	assert.Nil(t, flags.Lookup("redact"))
}

func TestAddSharedRedactFlagRegistersFlag(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{Use: "test"}
	addSharedRedactFlag(cmd)

	flags := cmd.Flags()
	redactFlag := flags.Lookup("redact")
	require.NotNil(t, redactFlag)
	assert.Equal(t, "false", redactFlag.DefValue)
}

func TestAddDisplayFlagsRegistersTheme(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	addDisplayFlags(cmd)

	flags := cmd.Flags()
	require.NotNil(t, flags.Lookup("theme"))
}

func TestValidFormats(t *testing.T) {
	t.Parallel()
	completions, directive := ValidFormats(nil, nil, "")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	require.Len(t, completions, 5)
	// Verify all formats are present (sorted alphabetically by the registry)
	assert.Contains(t, completions[0], "html")
	assert.Contains(t, completions[1], "json")
	assert.Contains(t, completions[2], "markdown")
	assert.Contains(t, completions[3], "text")
	assert.Contains(t, completions[4], "yaml")
}

func TestValidThemes(t *testing.T) {
	t.Parallel()
	completions, directive := ValidThemes(nil, nil, "")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	require.Len(t, completions, 4)
}

func TestValidSections(t *testing.T) {
	t.Parallel()
	completions, directive := ValidSections(nil, nil, "")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	require.Len(t, completions, 5)
}

func TestValidColorModes(t *testing.T) {
	t.Parallel()
	completions, directive := ValidColorModes(nil, nil, "")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	require.Len(t, completions, 3)
}

func TestValidDeviceTypes(t *testing.T) {
	t.Parallel()
	completions, directive := ValidDeviceTypes(nil, nil, "")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	// At least the built-in opnsense type must be present; additional entries
	// may exist from other tests registering custom device types on the global
	// singleton registry.
	require.GreaterOrEqual(t, len(completions), 1)

	found := false
	for _, c := range completions {
		if strings.Contains(c, "opnsense") {
			found = true
			break
		}
	}
	assert.True(t, found, "opnsense should be in completions")
}

func TestValidateDeviceType(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "empty auto-detects",
			value:   "",
			wantErr: false,
		},
		{
			name:    "opnsense lowercase",
			value:   "opnsense",
			wantErr: false,
		},
		{
			name:    "OPNSENSE uppercase",
			value:   "OPNSENSE",
			wantErr: false,
		},
		{
			name:    "pfsense supported",
			value:   "pfsense",
			wantErr: false,
		},
		{
			name:      "xyz unsupported",
			value:     "xyz",
			wantErr:   true,
			errSubstr: "unsupported device type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore sharedDeviceType
			origDeviceType := sharedDeviceType
			t.Cleanup(func() { sharedDeviceType = origDeviceType })

			sharedDeviceType = tt.value
			err := validateDeviceType()

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateDeviceType_CustomRegisteredType(t *testing.T) {
	// Register a custom device type that is not in the built-in enum.
	// Use a unique name to avoid collisions with other tests on the global registry.
	const customType = "customfirewall-validate-test"

	parser.DefaultRegistry().Register(customType, func(_ parser.XMLDecoder) parser.DeviceParser {
		return nil // placeholder; only testing validation, not parsing
	})

	origDeviceType := sharedDeviceType
	t.Cleanup(func() { sharedDeviceType = origDeviceType })

	sharedDeviceType = customType
	err := validateDeviceType()
	require.NoError(t, err, "custom registry-registered device type should pass validation")
}

func TestResolveDeviceType(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected common.DeviceType
	}{
		{
			name:     "empty returns DeviceTypeUnknown",
			value:    "",
			expected: common.DeviceTypeUnknown,
		},
		{
			name:     "opnsense returns built-in constant",
			value:    "opnsense",
			expected: common.DeviceTypeOPNsense,
		},
		{
			name:     "OPNsense case-insensitive returns built-in constant",
			value:    "OPNsense",
			expected: common.DeviceTypeOPNsense,
		},
		{
			name:     "pfsense returns built-in constant",
			value:    "pfsense",
			expected: common.DeviceTypePfSense,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origDeviceType := sharedDeviceType
			t.Cleanup(func() { sharedDeviceType = origDeviceType })

			sharedDeviceType = tt.value
			result := resolveDeviceType()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResolveDeviceType_CustomRegisteredType(t *testing.T) {
	// Register a custom type not in the built-in enum.
	const customType = "customfirewall-resolve-test"

	parser.DefaultRegistry().Register(customType, func(_ parser.XMLDecoder) parser.DeviceParser {
		return nil
	})

	origDeviceType := sharedDeviceType
	t.Cleanup(func() { sharedDeviceType = origDeviceType })

	sharedDeviceType = customType
	result := resolveDeviceType()

	// Should fall back to the normalized raw string, not DeviceTypeUnknown.
	assert.Equal(t, common.DeviceType(customType), result)
	assert.NotEqual(t, common.DeviceTypeUnknown, result)
}

func TestValidateDeviceType_ErrorUsesSupportedDevices(t *testing.T) {
	origDeviceType := sharedDeviceType
	t.Cleanup(func() { sharedDeviceType = origDeviceType })

	sharedDeviceType = "nonexistent-device"
	err := validateDeviceType()
	require.Error(t, err)

	// Error message should contain the centralized SupportedDevices() output.
	assert.Contains(t, err.Error(), parser.DefaultRegistry().SupportedDevices())
}
