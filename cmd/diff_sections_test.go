package cmd

import (
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/diff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateDiffFlags_AcceptsAliases pins the name by its literal text, so that
// the flag still takes it if the constant behind the engine's list is renamed.
func TestValidateDiffFlags_AcceptsAliases(t *testing.T) {
	snap := captureDiffFlags()
	t.Cleanup(snap.restore)

	diffFormat = DiffFormatTerminal
	diffMode = DiffModeUnified
	diffSections = []string{"aliases"}

	require.NoError(t, validateDiffFlags())
}

// TestValidateDiffFlags_MatchesImplementedSections ties the list validateDiffFlags
// keeps to the one the engine walks, in both directions: every section the engine
// compares is accepted, and every name shown in completion is accepted only if the
// engine implements it. A section missing from validateDiffFlags fails with
// "Invalid section" although the engine would compare it.
func TestValidateDiffFlags_MatchesImplementedSections(t *testing.T) {
	snap := captureDiffFlags()
	t.Cleanup(snap.restore)

	diffFormat = DiffFormatTerminal
	diffMode = DiffModeUnified

	for _, section := range diff.ImplementedSections() {
		diffSections = []string{section.String()}
		require.NoError(t, validateDiffFlags(), section.String())
	}

	completions, _ := ValidDiffSections(nil, nil, "")
	require.NotEmpty(t, completions)

	for _, completion := range completions {
		name, _, _ := strings.Cut(completion, "\t")
		diffSections = []string{name}
		assert.Equal(t, diff.Section(name).IsImplemented(), validateDiffFlags() == nil, name)
	}
}
