package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddSharedTemplateFlagsRegistersFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	addSharedTemplateFlags(cmd)

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
	// Verify all formats are present
	assert.Contains(t, completions[0], "markdown")
	assert.Contains(t, completions[1], "json")
	assert.Contains(t, completions[2], "yaml")
	assert.Contains(t, completions[3], "text")
	assert.Contains(t, completions[4], "html")
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
	require.Len(t, completions, 1)
	assert.Contains(t, completions[0], "opnsense")
}

func TestValidateDeviceType(t *testing.T) {
	t.Parallel()

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
			name:      "pfsense unsupported",
			value:     "pfsense",
			wantErr:   true,
			errSubstr: "unsupported device type",
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
			t.Parallel()

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
