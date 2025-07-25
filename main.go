// Package main is the entry point for the opnFocus CLI tool.
package main

import (
	"context"
	"opnFocus/cmd"
	"os"

	"github.com/charmbracelet/fang"
)

// main is the entry point for the opnFocus CLI tool, executing the root command and exiting with status code 1 on error.
func main() {
	if err := fang.Execute(context.Background(), cmd.GetRootCmd()); err != nil {
		os.Exit(1)
	}
}
