// Package main is the entry point for the opnFocus CLI tool.
package main

import (
	"context"
	"os"

	"github.com/charmbracelet/fang"
	"github.com/unclesp1d3r/opnFocus/cmd"
)

// main is the entry point for the opnFocus CLI tool, executing the root command and exiting with status code 1 on error.
func main() {
	if err := fang.Execute(context.Background(), cmd.GetRootCmd()); err != nil {
		// fang.Execute already handles error output, so we just need to exit
		os.Exit(1)
	}
}
