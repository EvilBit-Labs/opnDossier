package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCmd_HasJSONOutputFlag(t *testing.T) {
	// --json-output must be available on the validate command.
	// After the flag was moved from rootCmd persistent to validateCmd local,
	// this test ensures the contract is preserved (issue #479).
	flag := validateCmd.Flags().Lookup("json-output")
	require.NotNil(t, flag, "--json-output should be available on the validate command")
	assert.Equal(t, "bool", flag.Value.Type())
	assert.Equal(t, "false", flag.DefValue)
}
