// Package main is the entry point for the opnFocus CLI tool.
package main

import (
	"context"
	"opnFocus/cmd"
	"os"

	"github.com/charmbracelet/fang"
)

func main() {
	if err := fang.Execute(context.Background(), cmd.GetRootCmd()); err != nil {
		os.Exit(1)
	}
}
