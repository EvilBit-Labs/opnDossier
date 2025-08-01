// Package main is the entry point for the opnFocus CLI tool.
package main

import (
	"context"
	"os"

	"github.com/charmbracelet/fang"
	"github.com/unclesp1d3r/opnFocus/cmd"
	"github.com/unclesp1d3r/opnFocus/internal/constants"
)

// Version information injected by GoReleaser via ldflags.
var (
	version = "dev"
	// commit and date are injected by GoReleaser but not currently used
	// They are kept for potential future use.
	_ = "unknown" // commit
	_ = "unknown" // date
)

// init updates the version variable with injected values from GoReleaser.
func init() {
	// Update the version variable with injected values if they're not the defaults
	if version != "dev" {
		constants.Version = version
	}
}

// main starts the opnFocus CLI tool, executing the root command and exiting with status code 1 if an error occurs.
func main() {
	if err := fang.Execute(context.Background(), cmd.GetRootCmd()); err != nil {
		// fang.Execute already handles error output, so we just need to exit
		os.Exit(1)
	}
}
