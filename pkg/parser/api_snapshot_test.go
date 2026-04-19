// Package parser_test contains goldie-backed snapshots of the full `go doc
// -all` output for each public pkg/ package. Any accidental change to the
// exported surface — a renamed type, a new method, a rewritten doc comment,
// a deleted constant — shows up as a diff on the fixture files under
// pkg/parser/testdata/api-snapshots/ during code review.
//
// To regenerate the fixtures after an intentional API change:
//
//	go test ./pkg/parser/... -run TestPublicAPISnapshot -update
//
// Review the diff carefully — every new symbol in the snapshot becomes a
// stability commitment under the semver rules in
// docs/development/public-api.md.
package parser_test

import (
	"os/exec"
	"testing"

	"github.com/sebdah/goldie/v2"
	"github.com/stretchr/testify/require"
)

// apiSnapshotFixtureDir is the shared testdata location for every public-API
// snapshot fixture. All four packages (pkg/parser, pkg/parser/opnsense,
// pkg/parser/pfsense, pkg/model) write into the same directory under different
// fixture names so reviewers can see all API changes in one diff.
const apiSnapshotFixtureDir = "testdata/api-snapshots"

// captureGoDoc runs `go doc -all <packagePath>` and returns the raw output.
// `go doc` already restricts output to exported identifiers by default; the
// -all flag expands coverage to include every exported identifier in the
// package along with their associated doc comments, which is the full public
// surface we want to snapshot. The command is run under the test's context so
// `go test` timeout propagation and cancellation work correctly.
func captureGoDoc(t *testing.T, packagePath string) []byte {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), "go", "doc", "-all", packagePath)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go doc -all %s failed: %s", packagePath, out)

	return out
}

// newAPISnapshotGoldie returns a goldie instance configured for api-snapshot
// fixtures (shared fixture dir, .golden suffix, colored diff on failure).
func newAPISnapshotGoldie(t *testing.T) *goldie.Goldie {
	t.Helper()

	return goldie.New(
		t,
		goldie.WithFixtureDir(apiSnapshotFixtureDir),
		goldie.WithNameSuffix(".golden"),
		goldie.WithDiffEngine(goldie.ColoredDiff),
	)
}

// TestPublicAPISnapshot_pkg_parser captures the go-doc surface of pkg/parser.
// Regenerate with `go test ./pkg/parser/... -run TestPublicAPISnapshot -update`.
func TestPublicAPISnapshot_pkg_parser(t *testing.T) {
	t.Parallel()

	out := captureGoDoc(t, "github.com/EvilBit-Labs/opnDossier/pkg/parser")
	newAPISnapshotGoldie(t).Assert(t, "pkg-parser", out)
}

// TestPublicAPISnapshot_pkg_parser_opnsense captures the go-doc surface of
// pkg/parser/opnsense.
func TestPublicAPISnapshot_pkg_parser_opnsense(t *testing.T) {
	t.Parallel()

	out := captureGoDoc(t, "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense")
	newAPISnapshotGoldie(t).Assert(t, "pkg-parser-opnsense", out)
}

// TestPublicAPISnapshot_pkg_parser_pfsense captures the go-doc surface of
// pkg/parser/pfsense.
func TestPublicAPISnapshot_pkg_parser_pfsense(t *testing.T) {
	t.Parallel()

	out := captureGoDoc(t, "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense")
	newAPISnapshotGoldie(t).Assert(t, "pkg-parser-pfsense", out)
}

// TestPublicAPISnapshot_pkg_model captures the go-doc surface of pkg/model.
// pkg/model is the primary consumer contract; its snapshot is the largest of
// the four and should be reviewed carefully on every diff.
func TestPublicAPISnapshot_pkg_model(t *testing.T) {
	t.Parallel()

	out := captureGoDoc(t, "github.com/EvilBit-Labs/opnDossier/pkg/model")
	newAPISnapshotGoldie(t).Assert(t, "pkg-model", out)
}
