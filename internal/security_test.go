// Package internal holds repo-wide build-graph assertions and nothing else.
//
// It intentionally contains no non-test Go files, so `go build ./internal`
// reports "no non-test Go files" -- that is expected, not a breakage. Use
// `go vet ./internal`, `go test ./internal`, or a `./...` wildcard instead.
package internal

import (
	"bytes"
	"context"
	"go/build"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestNoNetworkDependencies verifies that the project has no network-making dependencies.
// This ensures the tool remains fully offline-capable for airgapped environments.
func TestNoNetworkDependencies(t *testing.T) {
	t.Parallel()

	// List of packages that could enable network connectivity
	forbiddenPackages := []string{
		"net/http",
		"net/rpc",
		"golang.org/x/net",
		// Analytics/telemetry packages
		"github.com/getsentry",
		"github.com/DataDog",
		"github.com/newrelic",
		"github.com/bugsnag",
		"gopkg.in/segmentio",
	}

	// Get the project root by looking at the parent of the internal package
	ctx := build.Default
	pkg, err := ctx.Import("github.com/EvilBit-Labs/opnDossier/internal", "", build.FindOnly)
	if err != nil {
		t.Skipf("Could not find package: %v", err)
	}

	projectRoot := filepath.Dir(pkg.Dir)

	// Check all Go files for forbidden imports
	err = filepath.Walk(projectRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip non-Go files and test files
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Skip vendor directory
		if strings.Contains(path, "/vendor/") {
			return nil
		}

		// Parse the file to check imports
		pkg, err := ctx.ImportDir(filepath.Dir(path), 0)
		if err != nil {
			// Skip if we can't parse (might be test-only file or build-tagged)
			// This is intentional - we want to continue walking even if one dir fails
			return nil //nolint:nilerr // Intentionally skip unparseable directories
		}

		for _, imp := range pkg.Imports {
			for _, forbidden := range forbiddenPackages {
				if strings.HasPrefix(imp, forbidden) {
					t.Errorf("Forbidden network package imported: %s in %s", imp, path)
				}
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk project: %v", err)
	}
}

// TestNoTelemetry verifies that no telemetry or analytics packages are used.
func TestNoTelemetry(t *testing.T) {
	t.Parallel()

	// Telemetry/analytics packages that should never be present
	telemetryPackages := []string{
		"sentry",
		"datadog",
		"newrelic",
		"bugsnag",
		"segment",
		"mixpanel",
		"amplitude",
		"posthog",
		"plausible",
	}

	ctx := build.Default
	pkg, err := ctx.Import("github.com/EvilBit-Labs/opnDossier", "", build.FindOnly)
	if err != nil {
		t.Skipf("Could not find package: %v", err)
	}

	// Check all imports for telemetry packages
	allImports := make(map[string]bool)
	for _, imp := range pkg.Imports {
		allImports[imp] = true
	}

	for _, telemetry := range telemetryPackages {
		for imp := range allImports {
			if strings.Contains(strings.ToLower(imp), telemetry) {
				t.Errorf("Telemetry package detected: %s", imp)
			}
		}
	}
}

// modulePath is this module's import path. Package paths in the reachability
// guard below are derived from it rather than repeated as literals.
const modulePath = "github.com/EvilBit-Labs/opnDossier"

// goListTimeout bounds each `go list` probe. The probes do not compile
// anything, so this is a hang guard rather than a performance budget.
const goListTimeout = 2 * time.Minute

// unreachableInternalPackages names the `./internal/...` packages that are
// deliberately outside the binary's transitive closure. Every entry carries the
// reason it is exempt; an unexplained entry would turn this guard into a rubber
// stamp.
//
// Adding a package here asserts that it exists to support tests or tooling and
// is intentionally not part of the shipped binary. Do NOT add a package here
// because nothing imports it any more -- delete the package instead. An
// unimported package that keeps attracting maintenance while reaching no user
// is exactly the drift this test exists to catch (issue #764).
//
//nolint:gochecknoglobals // package-level table read by the guard test below
var unreachableInternalPackages = map[string]string{
	modulePath + "/internal/testing/racedetect": "build-tagged test-only support; imported exclusively from _test.go files",
	modulePath + "/internal":                    "test-only package: holds this file's repo-wide build-graph assertions and nothing else",
	modulePath + "/internal/testing/modeltest":  "build-tagged (completeness) schema-coverage harness; run by `just completeness-check`, never linked into the binary",
}

// goListPackages runs `go list` with args and returns the package paths it
// printed. A failure here is a broken probe, not a finding, so it fails the
// test loudly rather than reporting an empty closure as a tree full of orphans.
func goListPackages(t *testing.T, args ...string) []string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), goListTimeout)
	defer cancel()

	// #nosec G204 -- args are test-owned literals, never external input.
	cmd := exec.CommandContext(ctx, "go", args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %s failed: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}

	return strings.Fields(string(out))
}

// binaryClosure returns the set of packages reachable from the main package as
// the shipped binary is built: default build tags, no test files.
//
// It deliberately does not union in a tag-enabled variant. `go list -deps`
// without `-test` never walks test-file imports, so a tag appearing only on
// _test.go files -- which is every build tag in this repo today -- cannot
// change the result. And a package reachable only under a non-default tag is
// by definition not in the shipped binary, so flagging it is correct; the
// allowlist is the escape hatch for the deliberate cases.
func binaryClosure(t *testing.T) map[string]bool {
	t.Helper()

	closure := make(map[string]bool)
	for _, pkg := range goListPackages(t, "list", "-deps", modulePath) {
		closure[pkg] = true
	}

	return closure
}

// internalPackages returns the import path of every package under internal/,
// discovered by walking the tree rather than by asking `go list ./internal/...`.
//
// This is load-bearing. `go list` silently omits a package whose files are all
// excluded by build constraints -- no error, no listing -- so a tag-gated
// package would be invisible to this guard on both ends: never flagged as an
// orphan, and never required to carry an exemption reason.
// internal/testing/modeltest (gated by `completeness`) is exactly that case.
// Walking the filesystem sees every package regardless of tags.
func internalPackages(t *testing.T) []string {
	t.Helper()

	// The test binary runs with its own package directory as the working
	// directory, so "." is internal/ itself.
	var pkgs []string

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// WalkDir never follows symlinks, so a package reachable only through
		// one would be invisible to this guard -- a silent hole in exactly the
		// check this test exists to provide. Fail loudly instead.
		if d.Type()&fs.ModeSymlink != 0 {
			t.Fatalf("symlink under internal/ (%s): the reachability walk cannot see through it; "+
				"replace it with a real directory or teach this guard how to resolve it", path)
		}

		if d.IsDir() {
			// Mirror the go tool's own rules: it ignores directories whose
			// names begin with "." or "_", and vendor trees.
			name := d.Name()
			if name != "." && (name == "testdata" || name == "vendor" ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return fs.SkipDir
			}

			return nil
		}

		if filepath.Ext(path) != ".go" {
			return nil
		}

		importPath := modulePath + "/internal"
		if dir := filepath.Dir(path); dir != "." {
			importPath += "/" + filepath.ToSlash(dir)
		}

		if !slices.Contains(pkgs, importPath) {
			pkgs = append(pkgs, importPath)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walking internal/ for packages: %v", err)
	}

	return pkgs
}

// TestAllInternalPackagesReachable verifies that every package under
// `./internal/...` is either in the binary's transitive dependency closure or
// explicitly exempted in unreachableInternalPackages.
//
// This is the recurrence guard for issue #764, where four packages sat outside
// the closure -- documented as live, absorbing real maintenance, and reaching
// no user. Nothing in the build catches that on its own: an unimported
// package still compiles, still passes its own tests, and still reports healthy
// coverage.
func TestAllInternalPackagesReachable(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not on PATH: %v", err)
	}

	reachable := binaryClosure(t)
	if len(reachable) == 0 {
		t.Fatal("dependency closure came back empty: the go list probe is broken, not the tree")
	}

	var orphans []string

	for _, pkg := range internalPackages(t) {
		if reachable[pkg] {
			continue
		}

		if _, exempt := unreachableInternalPackages[pkg]; exempt {
			continue
		}

		orphans = append(orphans, pkg)
	}

	if len(orphans) > 0 {
		slices.Sort(orphans)
		t.Errorf(
			"%d internal package(s) are outside the binary's dependency closure and not exempted:\n  %s\n\n"+
				"Each is dead code: nothing in the shipped binary can reach it. Either wire it into a real "+
				"consumer, or delete it. If it is genuinely test-only support, add it to "+
				"unreachableInternalPackages with the reason. See issue #764.",
			len(orphans), strings.Join(orphans, "\n  "),
		)
	}
}
