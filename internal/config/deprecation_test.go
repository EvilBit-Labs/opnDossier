// Package config deprecation-warning regression tests.
//
// These tests pin the v1.x→v2.0 migration signal produced by
// LoadConfigWithViper. They exist specifically to exercise the deprecated
// flat fields (Verbose, Debug, Quiet, Theme, Format) and their runtime
// detection, so SA1019 noise is intentional and suppressed via the
// file-level rule in .golangci.yml matching internal/config/*_test.go.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeprecationWarnings_EmptyByDefault asserts that a default config with
// no user input produces no deprecation warnings. Defaults must never be
// reported — otherwise every single run would warn.
func TestDeprecationWarnings_EmptyByDefault(t *testing.T) {
	clearEnvironment(t)

	cfg, err := LoadConfigWithViper("", viper.New())
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Empty(t, cfg.DeprecationWarnings(), "defaults must not trigger deprecation warnings")
}

// TestDeprecationWarnings_FromYAMLFile asserts that every deprecated flat
// key set via YAML produces exactly one corresponding warning.
func TestDeprecationWarnings_FromYAMLFile(t *testing.T) {
	clearEnvironment(t)

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.xml")
	require.NoError(t, os.WriteFile(inputFile, []byte("<test/>"), 0o600))

	cfgFilePath := filepath.Join(tmpDir, ".opnDossier.yaml")
	content := fmt.Sprintf(`
input_file: %s
verbose: true
debug: true
quiet: false
theme: dark
format: yaml
`, inputFile)
	require.NoError(t, os.WriteFile(cfgFilePath, []byte(content), 0o600))

	cfg, err := LoadConfigWithViper(cfgFilePath, viper.New())
	require.NoError(t, err)
	require.NotNil(t, cfg)

	warnings := cfg.DeprecationWarnings()
	assert.Len(t, warnings, 5, "expected one warning per deprecated key present in YAML")

	// Assert each deprecated key appears exactly once in the warnings slice.
	deprecatedKeys := []string{"verbose", "debug", "quiet", "theme", "format"}
	for _, key := range deprecatedKeys {
		var hits int
		for _, w := range warnings {
			// Warnings quote the key as `verbose` (top-level) — the backtick
			// substring uniquely identifies the key without false matches.
			if assertContainsKey(w, key) {
				hits++
			}
		}
		assert.Equal(t, 1, hits, "expected exactly one warning for key %q, got %d", key, hits)
	}
}

// TestDeprecationWarnings_FromEnvVar asserts that env-var overrides trigger
// the warning even when the value equals the default. This is intentional:
// explicit user input is reported, defaults are not.
func TestDeprecationWarnings_FromEnvVar(t *testing.T) {
	clearEnvironment(t)

	// Set a single deprecated key via env var. Value is "false" (matches
	// default) — the warning fires because the key was explicitly set,
	// not because the value differs.
	t.Setenv("OPNDOSSIER_VERBOSE", "false")

	cfg, err := LoadConfigWithViper("", viper.New())
	require.NoError(t, err)
	require.NotNil(t, cfg)

	warnings := cfg.DeprecationWarnings()
	require.Len(t, warnings, 1, "env-var override must trigger a warning")
	assert.True(t, assertContainsKey(warnings[0], "verbose"))
}

// TestDeprecationWarnings_NilReceiver guards against nil-config panics in
// callers that defensively invoke DeprecationWarnings() on *Config values
// from ambient contexts.
func TestDeprecationWarnings_NilReceiver(t *testing.T) {
	var cfg *Config
	assert.Nil(t, cfg.DeprecationWarnings())
}

// assertContainsKey reports whether a warning string references the given
// deprecated key. Warnings wrap keys in backticks (e.g. "`verbose` (top-level)"),
// so the backtick form is the uniquely identifying substring.
func assertContainsKey(warning, key string) bool {
	return strings.Contains(warning, "`"+key+"`")
}
