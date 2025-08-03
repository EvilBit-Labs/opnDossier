// Package main is the entry point for the opnDossier CLI tool.
package main

import (
	"context"
	"embed"
	"os"

	"github.com/EvilBit-Labs/opnDossier/cmd"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/markdown"
	"github.com/charmbracelet/fang"
)

// EmbeddedTemplates contains all template files embedded from internal/templates.
// This variable is initialized at compile time with all .tmpl files from the templates directory.
// It is passed to other packages during initialization via SetEmbeddedTemplates calls.
//
//go:embed internal/templates/*.tmpl internal/templates/reports/*.tmpl
var EmbeddedTemplates embed.FS

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

	// Initialize embedded templates for the markdown package
	markdown.SetEmbeddedTemplates(EmbeddedTemplates)
}

// main starts the opnDossier CLI tool, executing the root command and exiting with status code 1 if an error occurs.
func main() {
	if err := fang.Execute(context.Background(), cmd.GetRootCmd()); err != nil {
		// fang.Execute already handles error output, so we just need to exit
		os.Exit(1)
	}
}
