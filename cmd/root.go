package cmd

import (
	"fmt"
	"opnFocus/internal/config"
	"os"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
)

var (
	cfgFile string //nolint:gochecknoglobals // CLI config file path
	// Cfg holds the application's configuration, loaded from file, environment, or flags.
	Cfg    *config.Config //nolint:gochecknoglobals // Application configuration
	logger *log.Logger    //nolint:gochecknoglobals // Application logger
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra root command
	Use:   "opnFocus",
	Short: "opnFocus: A CLI tool for processing OPNsense configuration files.",
	Long: `opnFocus is a command-line interface (CLI) tool designed to process OPNsense firewall
configuration files (config.xml) and convert them into human-readable formats,
primarily Markdown. This tool is built to assist network administrators and
security professionals in documenting, auditing, and understanding their
OPNsense configurations more effectively.


Examples:
  # Convert an OPNsense config.xml to markdown and print to console
  opnFocus convert config.xml

  # Convert an OPNsense config.xml to markdown and save to a file
  opnFocus convert config.xml -o output.md
`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		var err error
		Cfg, err = config.LoadConfig(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		quiet, err := cmd.Flags().GetBool("quiet")
		if err != nil {
			return fmt.Errorf("failed to get quiet flag: %w", err)
		}
		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			return fmt.Errorf("failed to get verbose flag: %w", err)
		}

		if quiet {
			logger.SetLevel(log.ErrorLevel)
		} else if verbose || Cfg.Verbose {
			logger.SetLevel(log.DebugLevel)
		} else {
			logger.SetLevel(log.InfoLevel)
		}
		return nil
	},
}

func init() {
	logger = log.NewWithOptions(os.Stderr, log.Options{
		ReportCaller:    true,
		ReportTimestamp: true,
	})

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.opnFocus.yaml)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output (debug logging)")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress all output except errors")
}

// GetRootCmd returns the root command for the application.
func GetRootCmd() *cobra.Command {
	return rootCmd
}
