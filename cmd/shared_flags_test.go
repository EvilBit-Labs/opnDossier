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
}

func TestAddDisplayFlagsRegistersTheme(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	addDisplayFlags(cmd)

	flags := cmd.Flags()
	require.NotNil(t, flags.Lookup("theme"))
}
