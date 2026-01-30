// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"github.com/spf13/cobra"
)

// configCmd is the parent command for configuration management subcommands.
var configCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:     "config",
	Short:   "Manage opnDossier configuration",
	GroupID: "utility",
	Long: `The 'config' command group provides utilities for managing opnDossier configuration.

Subcommands:
  show      Display the effective configuration with source indicators
  init      Generate a template configuration file with all options commented
  validate  Validate a configuration file for syntax and semantic errors

Examples:
  # Show current effective configuration
  opnDossier config show

  # Show configuration in JSON format
  opnDossier config show --json

  # Generate a new configuration template
  opnDossier config init

  # Generate template at a specific path
  opnDossier config init --output ~/.opnDossier.yaml

  # Validate an existing configuration file
  opnDossier config validate ~/.opnDossier.yaml`,
}

// init registers the config command with the root command.
func init() {
	rootCmd.AddCommand(configCmd)
}
