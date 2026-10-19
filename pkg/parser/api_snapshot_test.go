// Package parser_test contains goldie-backed snapshots of the full `go doc
// -all` output for each public pkg/ package. Any accidental change to the
// exported surface — a renamed type, a new method, a rewritten doc comment,
// a deleted constant — shows up as a diff on the fixture files under
// pkg/parser/testdata/api-snapshots/ during code review.
//
// pkg/schema/* is covered here too. Those packages track the vendor file
// shape rather than opnDossier's own cadence, so a field type or a
// serialization tag there changes on the vendor's schedule — but the change
// is still visible to anyone marshalling those types, and until these
// fixtures existed it produced no diff for a reviewer to catch. PR #822
// removed SysctlItem.Item and retyped Group.Member and Group.Priv from string
// to []string past review for exactly that reason. go doc renders struct
// tags, so a tag rename shows up here as a one-line diff.
//
// To regenerate the fixtures after an intentional API change:
//
//	go test ./pkg/parser -run TestPublicAPISnapshot -update
//
// Review the diff carefully — every new symbol in a pkg/parser or pkg/model
// snapshot becomes a stability commitment under the semver rules in
// docs/development/public-api.md. The pkg/schema fixtures are different:
// those types follow the vendor's config.xml shape and are exempt from that
// commitment, so a diff there is a change to make visible and deliberate,
// not one to block.
package parser_test

import (
	"os/exec"
	"testing"

	"github.com/sebdah/goldie/v2"
	"github.com/stretchr/testify/require"
)

// apiSnapshotFixtureDir is the shared testdata location for every public-API
// snapshot fixture. Every covered package (pkg/parser, pkg/parser/opnsense,
// pkg/parser/pfsense, pkg/model, and the three under pkg/schema) writes into
// the same directory under a different fixture name, so reviewers see all API
// changes in one diff.
const apiSnapshotFixtureDir = "testdata/api-snapshots"

// captureGoDoc runs `go doc -all <packagePath>` and returns the raw output.
// Without `-all`, go doc prints a one-line summary per exported symbol;
// `-all` prints the full doc comment, struct fields and tags for each.
// Neither flag emits unexported identifiers (that is `-u`) or function
// bodies (`-src`), so the raw output is exactly the exported surface and
// needs no further filtering.
//
// CombinedOutput is used so `go doc` diagnostics emitted to stderr land in
// the failure message — otherwise a missing or mistyped package path fails
// the test with no context. The command runs under the test's context so
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
// Regenerate with `go test ./pkg/parser -run TestPublicAPISnapshot -update`.
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
// pkg/model is the primary consumer contract; its snapshot is the largest
// fixture and should be reviewed carefully on every diff.
func TestPublicAPISnapshot_pkg_model(t *testing.T) {
	t.Parallel()

	out := captureGoDoc(t, "github.com/EvilBit-Labs/opnDossier/pkg/model")
	newAPISnapshotGoldie(t).Assert(t, "pkg-model", out)
}

// TestPublicAPISnapshot_pkg_schema_opnsense captures the go-doc surface of
// pkg/schema/opnsense.
//
// This is the largest schema package and the one both vendors' converters
// read from, so a field removed or retyped here reaches every consumer of
// the parsed document.
func TestPublicAPISnapshot_pkg_schema_opnsense(t *testing.T) {
	t.Parallel()

	out := captureGoDoc(t, "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense")
	newAPISnapshotGoldie(t).Assert(t, "pkg-schema-opnsense", out)
}

// TestPublicAPISnapshot_pkg_schema_pfsense captures the go-doc surface of
// pkg/schema/pfsense.
//
// The pfSense types are a copy-on-write fork of their OPNsense counterparts,
// so this fixture is where the two drifting apart becomes visible.
func TestPublicAPISnapshot_pkg_schema_pfsense(t *testing.T) {
	t.Parallel()

	out := captureGoDoc(t, "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense")
	newAPISnapshotGoldie(t).Assert(t, "pkg-schema-pfsense", out)
}

// TestPublicAPISnapshot_pkg_schema_shared captures the go-doc surface of
// pkg/schema/shared.
func TestPublicAPISnapshot_pkg_schema_shared(t *testing.T) {
	t.Parallel()

	out := captureGoDoc(t, "github.com/EvilBit-Labs/opnDossier/pkg/schema/shared")
	newAPISnapshotGoldie(t).Assert(t, "pkg-schema-shared", out)
}
