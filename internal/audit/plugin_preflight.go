package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/logging"
)

// Phase A plugin loader hardening constants. These bound the preflight
// behaviour and are exported as package-level const so tests and docs can
// reference a single source of truth. Phase B follow-ups (owner-UID check,
// path denylist, filename allowlist, SHA-256 manifest) are tracked for
// post-v1.5; see GOTCHAS §2.5.
const (
	// pluginWritableMask matches the group-write and world-write bits
	// (0o020 | 0o002 = 0o022). Any file or directory carrying one of these
	// bits is writable by an account other than the plugin owner and is
	// therefore rejected by the preflight.
	pluginWritableMask os.FileMode = 0o022

	// pluginMaxSize caps the number of bytes we will read while computing
	// the SHA-256 digest for the audit log. A legitimate compliance plugin
	// is well under a megabyte; 64 MiB leaves generous headroom while
	// preventing pathological files from exhausting memory during preflight.
	// This also partially addresses the Phase B "size cap" objective.
	pluginMaxSize int64 = 64 << 20 // 64 MiB

	// pluginVerdictAccepted / pluginVerdictRejected are the two possible
	// outcomes logged by the preflight. Consumers of the audit log (SIEM,
	// log aggregator) can filter on these verdict strings.
	pluginVerdictAccepted = "accepted"
	pluginVerdictRejected = "rejected"
)

// pluginPreflightResult captures the metadata collected while validating a
// plugin file before we hand it to plugin.Open. It exists to make the audit
// log structure explicit and to keep the preflight call site in
// LoadDynamicPlugins readable.
type pluginPreflightResult struct {
	name      string
	path      string
	sha256    string
	mode      os.FileMode
	ownerUID  string // stringified UID, or "unavailable" on platforms where it cannot be read
	mtime     time.Time
	sizeBytes int64
	verdict   string
	reason    string
	err       error // non-nil when verdict == pluginVerdictRejected
}

// runPluginPreflight performs the Phase A hardening checks documented in
// GOTCHAS §2.5. It returns a pluginPreflightResult describing the outcome; on
// success the caller should proceed with plugin.Open, on rejection the
// caller should record the embedded error as a PluginLoadError.
//
// The checks, in order:
//  1. The path must be absolute (cross-platform).
//  2. Lstat the path. A symlink is rejected outright because plugin.Open
//     follows links (POSIX only — Windows symlink semantics differ and are
//     skipped at runtime).
//  3. Reject group/world-writable plugin files (POSIX only).
//  4. Stat the containing directory; reject if group/world-writable (POSIX
//     only).
//  5. Compute the file SHA-256 using a size-capped reader so the audit log
//     can identify the artifact even when the file cannot be opened as a
//     plugin.
//
// The returned pluginPreflightResult always contains the fields needed for a
// structured audit log, even on rejection.
func runPluginPreflight(path string) pluginPreflightResult {
	res := pluginPreflightResult{
		name:     filepath.Base(path),
		path:     path,
		ownerUID: "unavailable",
		verdict:  pluginVerdictRejected,
	}

	if !filepath.IsAbs(path) {
		res.reason = "plugin path is not absolute"
		res.err = fmt.Errorf("refusing plugin with relative path: %s", path)
		return res
	}

	info, err := os.Lstat(path)
	if err != nil {
		res.reason = "lstat failed"
		res.err = fmt.Errorf("failed to stat plugin %q: %w", path, err)
		return res
	}

	res.mode = info.Mode()
	res.mtime = info.ModTime()
	res.sizeBytes = info.Size()
	res.ownerUID = extractOwnerUID(info)

	// Symlink rejection. On Windows the ModeSymlink bit is present but
	// interpreted differently (junctions, reparse points); we still reject
	// symlinks there because plugin.Open would follow them and bypass our
	// checks on the target.
	if info.Mode()&os.ModeSymlink != 0 {
		res.reason = "plugin is a symlink"
		res.err = fmt.Errorf("refusing to load plugin symlink: %s", path)
		return res
	}

	// Permission-bit checks are POSIX-specific; NTFS permissions do not map
	// onto the os.FileMode.Perm() bits in a meaningful way.
	if runtime.GOOS != "windows" {
		if info.Mode().Perm()&pluginWritableMask != 0 {
			res.reason = fmt.Sprintf(
				"plugin file has group/world-writable mode %#o",
				info.Mode().Perm(),
			)
			res.err = fmt.Errorf(
				"refusing plugin with group/world-writable mode %#o: %s",
				info.Mode().Perm(), path,
			)
			return res
		}

		dirPath := filepath.Dir(path)
		dirInfo, statErr := os.Stat(dirPath)
		if statErr != nil {
			res.reason = "stat of plugin directory failed"
			res.err = fmt.Errorf("failed to stat plugin directory %q: %w", dirPath, statErr)
			return res
		}

		if dirInfo.Mode().Perm()&pluginWritableMask != 0 {
			res.reason = fmt.Sprintf(
				"plugin directory has group/world-writable mode %#o",
				dirInfo.Mode().Perm(),
			)
			res.err = fmt.Errorf(
				"refusing plugin in group/world-writable directory %q (mode %#o)",
				dirPath, dirInfo.Mode().Perm(),
			)
			return res
		}
	}

	// Compute SHA-256 before handing the file to plugin.Open. Do this last
	// so cheap rejections short-circuit without reading file contents. The
	// read is capped at pluginMaxSize to bound memory and I/O.
	digest, hashErr := hashFileSizeCapped(path, pluginMaxSize)
	if hashErr != nil {
		res.reason = "sha256 computation failed"
		res.err = fmt.Errorf("failed to hash plugin %q: %w", path, hashErr)
		return res
	}

	res.sha256 = digest
	res.verdict = pluginVerdictAccepted
	res.reason = "preflight checks passed"
	return res
}

// hashFileSizeCapped returns the hex-encoded SHA-256 of the file at path,
// reading at most maxBytes+1 so files exceeding the cap are rejected rather
// than silently truncated. A zero-byte cap disables the cap.
func hashFileSizeCapped(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	hasher := sha256.New()

	var n int64
	if maxBytes > 0 {
		// Read one extra byte so we can detect files that exceed the cap
		// without truncating silently. io.CopyN returns io.EOF when the
		// file is smaller than limit; anything else means we hit the cap.
		n, err = io.CopyN(hasher, f, maxBytes+1)
		switch {
		case errors.Is(err, io.EOF):
			// File fit under the cap — expected path.
		case err != nil:
			return "", fmt.Errorf("read %q: %w", path, err)
		case n > maxBytes:
			return "", fmt.Errorf("plugin %q exceeds size cap of %d bytes", path, maxBytes)
		}
	} else {
		if _, err := io.Copy(hasher, f); err != nil {
			return "", fmt.Errorf("read %q: %w", path, err)
		}
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// logPreflight emits a structured audit-log entry describing the outcome of
// a plugin preflight. Every attempted load produces exactly one entry, at
// INFO for accepted loads and WARN for rejections, so operators can filter
// by verdict without losing any attempts.
func logPreflight(logger *logging.Logger, res pluginPreflightResult) {
	fields := []any{
		"plugin", res.name,
		"path", res.path,
		"sha256", res.sha256,
		"mode", fmt.Sprintf("%#o", res.mode.Perm()),
		"owner_uid", res.ownerUID,
		"mtime", res.mtime.UTC().Format(time.RFC3339Nano),
		"size_bytes", res.sizeBytes,
		"verdict", res.verdict,
		"reason", res.reason,
	}

	if res.verdict == pluginVerdictAccepted {
		logger.Info("plugin preflight", fields...)
		return
	}

	logger.Warn("plugin preflight", fields...)
}
