package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
)

// goosWindows is the runtime.GOOS value used throughout the hardening
// tests to decide whether POSIX-only assertions should be skipped.
const goosWindows = "windows"

// writePluginFile creates a .so file with the given name, mode, and content
// inside dir. It fails the test on I/O errors. Callers are expected to use
// this helper for every preflight hardening fixture so chmod/cleanup is
// centralized.
func writePluginFile(t *testing.T, dir, name string, mode os.FileMode, content []byte) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("failed to write plugin fixture %q: %v", path, err)
	}
	// os.WriteFile honours the umask on POSIX, so we chmod explicitly to
	// get the exact bits the test is asserting against.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("failed to chmod plugin fixture %q to %#o: %v", path, mode, err)
	}

	return path
}

// alwaysFailLoader returns a pluginLoaderFunc that unconditionally errors.
// Used by hardening tests to prove the preflight rejected the file without
// ever dispatching to the loader.
func alwaysFailLoader() pluginLoaderFunc {
	return func(path string) (compliance.Plugin, error) {
		return nil, fmt.Errorf("loader should not have been invoked for %q", path)
	}
}

// bufferLogger returns a Logger backed by a bytes.Buffer so tests can
// inspect the structured audit log.
func bufferLogger(t *testing.T) (*logging.Logger, *bytes.Buffer) {
	t.Helper()

	var buf bytes.Buffer
	logger, err := logging.New(logging.Config{
		Level:  "debug",
		Output: &buf,
	})
	if err != nil {
		t.Fatalf("failed to create buffer logger: %v", err)
	}

	return logger, &buf
}

// TestLoadDynamicPlugins_RejectsSymlink verifies that a symlink pointing at
// a valid target is refused by the preflight.
//
// Cross-platform: skipped on Windows. os.Symlink requires Developer Mode or
// admin rights on Windows and semantics (junctions, reparse points) differ
// enough that a dedicated Windows-native test should cover that case.
func TestLoadDynamicPlugins_RejectsSymlink(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == goosWindows {
		t.Skip("symlink test requires symlink creation; Windows needs developer mode")
	}

	dir := t.TempDir()

	// Create a real .so-equivalent file outside the plugin dir so we can
	// verify the preflight flags the symlink itself, not the target.
	target := filepath.Join(t.TempDir(), "target.so")
	if err := os.WriteFile(target, []byte("stub"), 0o600); err != nil {
		t.Fatalf("failed to write symlink target: %v", err)
	}

	link := filepath.Join(dir, "linked.so")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	registry := newPluginRegistryWithLoader(alwaysFailLoader())
	logger := newTestLogger(t)

	result, err := registry.LoadDynamicPlugins(context.Background(), dir, true, logger)
	if err == nil {
		t.Fatal("LoadDynamicPlugins() expected error for symlink plugin")
	}

	if result.Failed() != 1 {
		t.Fatalf("Failed() = %d, want 1", result.Failed())
	}

	if !strings.Contains(result.Failures[0].Error(), "symlink") {
		t.Errorf("expected 'symlink' in failure error, got: %v", result.Failures[0].Err)
	}
}

// TestLoadDynamicPlugins_RejectsWorldWritableFile verifies that a .so with
// world-write bits (0o666) is rejected before plugin.Open.
//
// Cross-platform: skipped on Windows because NTFS permissions do not map
// onto os.FileMode.Perm() bits.
func TestLoadDynamicPlugins_RejectsWorldWritableFile(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == goosWindows {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}

	dir := t.TempDir()
	writePluginFile(t, dir, "writable.so", 0o666, []byte("stub"))

	registry := newPluginRegistryWithLoader(alwaysFailLoader())
	logger := newTestLogger(t)

	result, err := registry.LoadDynamicPlugins(context.Background(), dir, true, logger)
	if err == nil {
		t.Fatal("LoadDynamicPlugins() expected error for world-writable plugin")
	}

	if result.Failed() != 1 {
		t.Fatalf("Failed() = %d, want 1", result.Failed())
	}

	if !strings.Contains(result.Failures[0].Error(), "group/world-writable") {
		t.Errorf("expected 'group/world-writable' in failure, got: %v", result.Failures[0].Err)
	}
}

// TestLoadDynamicPlugins_RejectsGroupWritableFile verifies that a .so with
// group-write bits (0o664) is rejected even without world-write.
//
// Cross-platform: skipped on Windows for the same reason as the
// world-writable test.
func TestLoadDynamicPlugins_RejectsGroupWritableFile(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == goosWindows {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}

	dir := t.TempDir()
	writePluginFile(t, dir, "groupwritable.so", 0o664, []byte("stub"))

	registry := newPluginRegistryWithLoader(alwaysFailLoader())
	logger := newTestLogger(t)

	result, err := registry.LoadDynamicPlugins(context.Background(), dir, true, logger)
	if err == nil {
		t.Fatal("LoadDynamicPlugins() expected error for group-writable plugin")
	}

	if result.Failed() != 1 {
		t.Fatalf("Failed() = %d, want 1", result.Failed())
	}

	if !strings.Contains(result.Failures[0].Error(), "group/world-writable") {
		t.Errorf("expected 'group/world-writable' in failure, got: %v", result.Failures[0].Err)
	}
}

// TestLoadDynamicPlugins_RejectsWorldWritableContainerDir verifies that a
// properly permissioned plugin file inside a world-writable directory is
// still rejected.
//
// Cross-platform: skipped on Windows for the same reason as the other
// permission tests. We also chmod the container back to 0o700 before the
// t.TempDir cleanup runs so the parent RemoveAll does not fail.
func TestLoadDynamicPlugins_RejectsWorldWritableContainerDir(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == goosWindows {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}

	parent := t.TempDir()
	pluginDir := filepath.Join(parent, "plugins")
	if err := os.Mkdir(pluginDir, 0o700); err != nil {
		t.Fatalf("failed to create plugin dir: %v", err)
	}

	writePluginFile(t, pluginDir, "ok.so", 0o600, []byte("stub"))

	// Flip the container to world-writable AFTER writing the file so the
	// fixture creation itself is not complicated by the permissions.
	// gosec G302: intentional world-writable chmod — the whole point of
	// this test is to exercise the preflight's rejection of that mode.
	if err := os.Chmod(pluginDir, 0o777); err != nil { //nolint:gosec // intentional world-writable mode under test
		t.Fatalf("failed to chmod plugin dir to world-writable: %v", err)
	}
	t.Cleanup(func() {
		// Restore permissions so t.TempDir cleanup can remove the dir on
		// platforms where the test user cannot unlink files inside a
		// world-writable directory without write on the parent.
		//nolint:gosec // 0o700 is the default t.TempDir mode; explicit restore.
		if err := os.Chmod(pluginDir, 0o700); err != nil {
			t.Logf("warning: failed to restore plugin dir permissions: %v", err)
		}
	})

	registry := newPluginRegistryWithLoader(alwaysFailLoader())
	logger := newTestLogger(t)

	result, err := registry.LoadDynamicPlugins(context.Background(), pluginDir, true, logger)
	if err == nil {
		t.Fatal("LoadDynamicPlugins() expected error for plugin in world-writable dir")
	}

	if result.Failed() != 1 {
		t.Fatalf("Failed() = %d, want 1", result.Failed())
	}

	if !strings.Contains(result.Failures[0].Error(), "group/world-writable directory") {
		t.Errorf("expected 'group/world-writable directory' in failure, got: %v", result.Failures[0].Err)
	}
}

// TestLoadDynamicPlugins_RejectsRelativePath verifies that a plugin path
// computed against a non-absolute directory is rejected. We exercise this by
// chdir-ing into a tempdir that holds a .so and passing "." as the dir.
//
// Cross-platform: runs on all platforms — the absolute-path check is OS
// independent. Concurrency-sensitive because os.Chdir is process global,
// so this test does NOT call t.Parallel().
func TestLoadDynamicPlugins_RejectsRelativePath(t *testing.T) {
	// os.Chdir mutates process-global state; running in parallel would race
	// with every other test in the binary, so we intentionally omit
	// t.Parallel.

	dir := t.TempDir()
	writePluginFile(t, dir, "ok.so", 0o600, []byte("stub"))

	// t.Chdir (Go 1.24+) restores the previous working directory via
	// t.Cleanup automatically, so we avoid a bare os.Chdir that the
	// linter cannot prove safe.
	t.Chdir(dir)

	registry := newPluginRegistryWithLoader(alwaysFailLoader())
	logger := newTestLogger(t)

	// "." resolves to the plugin dir through os.ReadDir, but each path
	// passed to the preflight is still relative because filepath.Join(".",
	// "ok.so") stays relative.
	result, err := registry.LoadDynamicPlugins(context.Background(), ".", true, logger)
	if err == nil {
		t.Fatal("LoadDynamicPlugins() expected error for relative path")
	}

	if result.Failed() != 1 {
		t.Fatalf("Failed() = %d, want 1", result.Failed())
	}

	if !strings.Contains(result.Failures[0].Error(), "relative path") {
		t.Errorf("expected 'relative path' in failure, got: %v", result.Failures[0].Err)
	}
}

// TestLoadDynamicPlugins_RejectsNonELF verifies that a .so whose contents
// are not a valid shared object (random bytes) is rejected downstream by
// the plugin loader after preflight passes. This locks in the behaviour
// that preflight is not a substitute for plugin.Open's own validation.
//
// Cross-platform: runs on all platforms because we inject a deterministic
// loader that mimics plugin.Open's failure rather than invoking the real
// dynamic linker.
func TestLoadDynamicPlugins_RejectsNonELF(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePluginFile(t, dir, "garbage.so", 0o600, []byte{0x00, 0x01, 0x02, 0x03})

	registry := newPluginRegistryWithLoader(func(path string) (compliance.Plugin, error) {
		// Mimic what plugin.Open would do with non-ELF content: fail with
		// a clear error. We intentionally do not call plugin.Open here
		// because it would be platform-specific and the goal of this test
		// is to prove that loader failures after a clean preflight are
		// captured as PluginLoadError, not to test plugin.Open itself.
		return nil, fmt.Errorf("open %q: invalid ELF header", path)
	})
	logger := newTestLogger(t)

	result, err := registry.LoadDynamicPlugins(context.Background(), dir, true, logger)
	if err == nil {
		t.Fatal("LoadDynamicPlugins() expected error for non-ELF .so")
	}

	if result.Failed() != 1 {
		t.Fatalf("Failed() = %d, want 1", result.Failed())
	}

	if !strings.Contains(result.Failures[0].Error(), "invalid ELF header") {
		t.Errorf("expected loader error to surface, got: %v", result.Failures[0].Err)
	}
}

// TestLoadDynamicPlugins_AuditLogEmitted verifies that every load attempt —
// accepted or rejected — emits a structured audit log line with the
// expected fields.
//
// Cross-platform: runs on all platforms. On Windows the owner_uid field is
// always "unavailable"; the presence check still succeeds because the field
// key is emitted unconditionally.
func TestLoadDynamicPlugins_AuditLogEmitted(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePluginFile(t, dir, "audit.so", 0o600, []byte("stub"))

	// The loader fails deterministically so the plugin never registers;
	// we are only interested in the preflight-accepted audit line, which
	// is emitted before the loader runs.
	registry := newPluginRegistryWithLoader(func(path string) (compliance.Plugin, error) {
		return nil, fmt.Errorf("synthetic load failure for %q", path)
	})

	logger, buf := bufferLogger(t)

	// We expect a non-nil error (synthetic loader failure) but the
	// structured preflight log for the accepted file must still be
	// emitted before the loader runs.
	if _, err := registry.LoadDynamicPlugins(context.Background(), dir, true, logger); err == nil {
		t.Fatal("expected loader failure to bubble up as an error")
	}

	output := buf.String()

	// Must emit an INFO-level "plugin preflight" line because the
	// file passed every preflight check. Rejection paths would log at
	// WARN, which is asserted in TestLoadDynamicPlugins_AuditLog_RejectionWarn.
	if !strings.Contains(output, "plugin preflight") {
		t.Errorf("expected 'plugin preflight' audit message, log output:\n%s", output)
	}

	requiredFields := []string{
		"plugin=",
		"path=",
		"sha256=",
		"mode=",
		"owner_uid=",
		"mtime=",
		"size_bytes=",
		"verdict=",
		"reason=",
	}
	for _, field := range requiredFields {
		if !strings.Contains(output, field) {
			t.Errorf("audit log missing field %q; full output:\n%s", field, output)
		}
	}

	if !strings.Contains(output, "verdict=accepted") {
		t.Errorf("expected verdict=accepted for clean preflight, log output:\n%s", output)
	}
}

// TestLoadDynamicPlugins_AuditLog_RejectionWarn verifies that rejected
// plugins are logged at WARN level with verdict=rejected.
//
// Cross-platform: skipped on Windows because this test relies on a
// rejection (world-writable file) that requires POSIX permission semantics.
func TestLoadDynamicPlugins_AuditLog_RejectionWarn(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == goosWindows {
		t.Skip("rejection trigger requires POSIX permission bits")
	}

	dir := t.TempDir()
	writePluginFile(t, dir, "bad.so", 0o666, []byte("stub"))

	registry := newPluginRegistryWithLoader(alwaysFailLoader())
	logger, buf := bufferLogger(t)

	// The world-writable fixture is rejected by preflight, so an
	// aggregate error is expected; we consume it explicitly so errcheck
	// is satisfied and the test's intent is explicit.
	if _, err := registry.LoadDynamicPlugins(context.Background(), dir, true, logger); err == nil {
		t.Fatal("expected preflight rejection to bubble up as an error")
	}

	output := buf.String()

	if !strings.Contains(output, "WARN") {
		t.Errorf("expected WARN-level audit log for rejected plugin; log output:\n%s", output)
	}
	if !strings.Contains(output, "verdict=rejected") {
		t.Errorf("expected verdict=rejected in audit log; output:\n%s", output)
	}
}

// TestRunPluginPreflight_Unit exercises runPluginPreflight directly so we
// can assert on the structured result without going through the full
// LoadDynamicPlugins pipeline. Guards basic invariants: accepted paths carry
// a sha256 digest, rejections carry a non-nil err, and the verdict string
// stays within the two documented values.
func TestRunPluginPreflight_Unit(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == goosWindows {
		t.Skip("POSIX permission semantics required")
	}

	dir := t.TempDir()
	goodPath := writePluginFile(t, dir, "good.so", 0o600, []byte("payload"))

	t.Run("accepted plugin returns sha256", func(t *testing.T) {
		t.Parallel()

		res := runPluginPreflight(goodPath)
		if res.verdict != pluginVerdictAccepted {
			t.Fatalf("verdict = %q, want %q; reason=%s err=%v",
				res.verdict, pluginVerdictAccepted, res.reason, res.err)
		}
		if res.sha256 == "" {
			t.Error("accepted preflight should populate sha256")
		}
		if res.err != nil {
			t.Errorf("accepted preflight should not carry an error: %v", res.err)
		}
	})

	t.Run("relative path is rejected", func(t *testing.T) {
		t.Parallel()

		res := runPluginPreflight("relative/path.so")
		if res.verdict != pluginVerdictRejected {
			t.Fatalf("verdict = %q, want %q", res.verdict, pluginVerdictRejected)
		}
		if res.err == nil {
			t.Error("rejected preflight must carry an error")
		}
		if !strings.Contains(res.reason, "not absolute") {
			t.Errorf("expected reason to mention non-absolute path, got %q", res.reason)
		}
	})

	t.Run("missing file is rejected", func(t *testing.T) {
		t.Parallel()

		res := runPluginPreflight(filepath.Join(dir, "does-not-exist.so"))
		if res.verdict != pluginVerdictRejected {
			t.Fatalf("verdict = %q, want %q", res.verdict, pluginVerdictRejected)
		}
		if !errors.Is(res.err, os.ErrNotExist) {
			t.Errorf("expected error to wrap os.ErrNotExist, got %v", res.err)
		}
	})
}

// TestHashFileSizeCapped_ExceedsCap guards the 64 MiB size cap used by
// runPluginPreflight. Feeding it a 1 KiB cap with a 2 KiB file must return
// an "exceeds size cap" error rather than silently truncating.
func TestHashFileSizeCapped_ExceedsCap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "big.so")
	data := bytes.Repeat([]byte{0xAB}, 2048)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	_, err := hashFileSizeCapped(path, 1024)
	if err == nil {
		t.Fatal("expected error when file exceeds cap")
	}
	if !strings.Contains(err.Error(), "exceeds size cap") {
		t.Errorf("expected 'exceeds size cap' error, got: %v", err)
	}
}
