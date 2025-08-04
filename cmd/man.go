package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// manCmd represents the man command.
var manCmd = &cobra.Command{
	Use:   "man [output-directory]",
	Short: "Generate man pages",
	Long: `Generate man pages for opnDossier and all of its commands.

If no output directory is specified, man pages will be written to './man/'.

Example:
  opndossier man
  opndossier man /usr/local/share/man/man1/
`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		outputDir := "./man/"
		if len(args) > 0 {
			outputDir = args[0]
		}

		// Ensure the output directory exists
		//nolint:gosec // Man pages require 755 permissions for public access
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
		}

		// Set up the header for the man pages
		header := &doc.GenManHeader{
			Title:   "OPNDOSSIER",
			Section: "1",
			Source:  "opnDossier " + cmd.Root().Version,
		}

		// Generate man pages for all commands
		if err := doc.GenManTree(cmd.Root(), header, outputDir); err != nil {
			return fmt.Errorf("failed to generate man pages: %w", err)
		}

		fmt.Printf("Man pages generated successfully in %s\n", outputDir)

		// List the generated files
		files, err := filepath.Glob(filepath.Join(outputDir, "*.1"))
		if err == nil && len(files) > 0 {
			fmt.Println("Generated files:")
			for _, file := range files {
				fmt.Printf("  %s\n", file)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(manCmd)
}
