//go:build !windows

package audit

import (
	"os"
	"strconv"
	"syscall"
)

// extractOwnerUID returns the string-formatted UID of the file owner on
// POSIX platforms. If the underlying os.FileInfo does not carry a
// *syscall.Stat_t (e.g., custom FileInfo impls in tests) the function
// returns "unavailable" so the audit log can still record something
// deterministic instead of panicking.
func extractOwnerUID(info os.FileInfo) string {
	if info == nil {
		return "unavailable"
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return "unavailable"
	}

	return strconv.FormatUint(uint64(stat.Uid), 10)
}
