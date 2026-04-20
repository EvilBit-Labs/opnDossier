//go:build windows

package audit

import "os"

// extractOwnerUID returns a platform-neutral placeholder on Windows.
// NTFS ownership is expressed via SIDs, not numeric UIDs; mapping those
// into the POSIX-style audit field would create a false equivalence. Phase B
// hardening can introduce a dedicated Windows owner-check path if needed.
func extractOwnerUID(_ os.FileInfo) string {
	return "unavailable"
}
