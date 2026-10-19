// Package internal holds repo-wide build-graph assertions and nothing else.
//
// It intentionally contains no non-test Go files, so `go build ./internal`
// reports "no non-test Go files" -- that is expected, not a breakage. Use
// `go vet ./internal`, `go test ./internal`, or a `./...` wildcard instead.
package internal

import (
	"bytes"
	"context"
	"fmt"
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

		// .git holds no Go source, and its lock files appear and vanish while
		// the walk is in flight, which failed the walk on a Windows runner.
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
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
	root, err := ctx.Import(modulePath, "", build.FindOnly)
	if err != nil {
		t.Skipf("Could not find package: %v", err)
	}

	// build.FindOnly locates the directory without reading source, so
	// Package.Imports is always empty under it -- this loop used to iterate an
	// empty set and could not fail regardless of what was imported. Walk with
	// ImportDir(dir, 0), which actually parses, as TestNoNetworkDependencies does.
	inspected := 0

	err = filepath.Walk(root.Dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// See TestNoNetworkDependencies: .git is skipped as a directory.
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}

		if !info.IsDir() || strings.Contains(path, "/vendor/") {
			return nil
		}

		pkg, err := ctx.ImportDir(path, 0)
		if err != nil {
			// A directory with no buildable Go files is expected; keep walking.
			return nil //nolint:nilerr // Intentionally skip unparseable directories
		}

		inspected++

		for _, imp := range append(pkg.Imports, pkg.TestImports...) {
			for _, telemetry := range telemetryPackages {
				if strings.Contains(strings.ToLower(imp), telemetry) {
					t.Errorf("Telemetry package detected: %s in %s", imp, path)
				}
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk project: %v", err)
	}

	if inspected == 0 {
		t.Fatal("inspected no packages: the walk is broken, so a clean result proves nothing")
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
// It deliberately does not union in a tag-enabled variant, for two separate
// reasons. `go list -deps` without `-test` never walks test-file imports, so a
// tag carried only by _test.go files cannot change the result either way. And
// a package reachable only under a non-default tag -- internal/testing/modeltest
// behind `completeness`, for example -- is by definition absent from the
// shipped binary, so flagging it is the correct answer rather than a false
// positive; the allowlist is the escape hatch for those deliberate cases.
//
// Non-test files here do carry build constraints (GOOS splits in
// internal/audit, the race-detector shim, the completeness harness), so do not
// assume tags are a test-only concern in this repository.
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
			return fmt.Errorf("walking %s: %w", path, err)
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

	reachable := binaryClosure(t)
	if len(reachable) == 0 {
		t.Fatal("dependency closure came back empty: the go list probe is broken, not the tree")
	}

	// A walk that returns nothing -- wrong working directory, a refactor that
	// skips the root, a stray SkipDir -- would leave orphans empty and report
	// PASS while checking nothing: the same silent-pass inversion this guard
	// exists to catch, turned on the guard itself. Prove the walk found the
	// tree before trusting its verdict.
	discovered := internalPackages(t)
	if len(discovered) == 0 {
		t.Fatal("walk found no packages under internal/: the walk is broken, not the tree")
	}

	for _, sentinel := range []string{modulePath + "/internal/converter", modulePath + "/internal/analysis"} {
		if !slices.Contains(discovered, sentinel) {
			t.Fatalf(
				"walk did not find %s, so it is rooted somewhere unexpected and its verdict is meaningless",
				sentinel,
			)
		}
	}

	var orphans []string

	for _, pkg := range discovered {
		if reachable[pkg] {
			continue
		}

		if reason, exempt := unreachableInternalPackages[pkg]; exempt {
			// The allowlist's value is its whole point: an entry with no stated
			// reason is an unexplained exemption, which is the rubber stamp this
			// guard exists to prevent.
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is exempted with no stated reason; give the entry a reason or delete the package", pkg)
			}

			continue
		}

		orphans = append(orphans, pkg)
	}

	// An exemption is a claim, and claims rot. A key naming a package that no
	// longer exists could be silently inherited by an unrelated future package
	// at the same path; a key since wired into the binary is simply stale.
	// Neither is reachable from the loop above -- reachable packages skip the
	// allowlist entirely.
	for pkg := range unreachableInternalPackages {
		if !slices.Contains(discovered, pkg) {
			t.Errorf("%s is exempted but no longer exists; remove the stale entry", pkg)
		}

		if reachable[pkg] {
			t.Errorf("%s is exempted but is now reachable from the binary; remove the obsolete entry", pkg)
		}
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
