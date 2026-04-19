// Package main is the entry point for the opnDossier CLI tool.
package main

import (
	"context"
	"log"
	"os"

	"github.com/EvilBit-Labs/opnDossier/cmd"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/charmbracelet/fang"
	"go.uber.org/automaxprocs/maxprocs"
)

// Version information injected by GoReleaser via ldflags.
var (
	version = "dev"
	// commit and date are injected by GoReleaser but not currently used
	// They are kept for potential future use.
	_ = "unknown" // commit
	_ = "unknown" // date
)

// init updates the package version with the build-time injected value when it is not the default "dev".
func init() {
	// Update the version variable with injected values if they're not the defaults
	if version != "dev" {
		constants.Version = version
	}
}

// main starts the opnDossier CLI tool, executing the root command and exiting with status code 1 if an error occurs.
func main() {
	// Align GOMAXPROCS with the Linux container CPU quota (Docker / Kubernetes
	// / cgroup-limited environments). Without this, runtime.NumCPU reports the
	// host CPU count, which oversizes the audit/convert concurrency semaphores
	// in cmd/audit.go and cmd/convert.go and leads to CPU throttling under
	// container limits. Using the explicit maxprocs.Set call (rather than the
	// `_ "go.uber.org/automaxprocs"` blank import) lets us surface the error
	// instead of silently logging through the library's default logger.
	// The undo function is discarded — there is no need to restore the
	// previous value since the process exits after the CLI completes.
	if _, err := maxprocs.Set(); err != nil {
		log.Printf("warning: failed to set GOMAXPROCS: %v", err)
	}

	if err := fang.Execute(context.Background(), cmd.GetRootCmd()); err != nil {
		// fang.Execute already handles error output, so we just need to exit
		os.Exit(1)
	}
}
