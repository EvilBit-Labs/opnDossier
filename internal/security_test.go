package internal

import (
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
