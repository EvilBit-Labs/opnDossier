// Package cmd provides the command-line interface for opnFocus.
package cmd

import (
	"fmt"
	"opnFocus/internal/converter"
	"opnFocus/internal/export"
	"opnFocus/internal/parser"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

var outputFile string //nolint:gochecknoglobals // CLI flag variable

func init() {
	rootCmd.AddCommand(convertCmd)
	convertCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
}

var convertCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:   "convert [file ...]",
	Short: "Convert OPNsense configuration files to markdown",
	Long: `The 'convert' command processes one or more OPNsense config.xml files and transforms
its content into a structured Markdown format. This allows for easier
readability, documentation, and auditing of your firewall configuration.

You can either print the generated Markdown directly to the console or
save it to a specified output file using the '--output' or '-o' flag.
When processing multiple files, the --output flag will be ignored, and
each output file will be named based on its input file (e.g., config.xml -> config.md).

Examples:
  # Convert 'my_config.xml' and print the Markdown to standard output
  opnFocus convert my_config.xml

  # Convert 'my_config.xml' and save the Markdown to 'documentation.md'
  opnFocus convert my_config.xml -o documentation.md

  # Convert multiple files and save them with .md extension
  opnFocus convert config1.xml config2.xml

  # Convert 'backup_config.xml' and enable verbose logging during the process
  opnFocus --verbose convert backup_config.xml
`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		var wg sync.WaitGroup
		errs := make(chan error, len(args))

		for _, filePath := range args {
			wg.Add(1)
			go func(fp string) {
				defer wg.Done()
				logger.Info("Starting conversion process", "input_file", fp)

				// Sanitize the file path
				cleanPath := filepath.Clean(fp)
				if !filepath.IsAbs(cleanPath) {
					// If not an absolute path, make it relative to the current working directory
					var err error
					cleanPath, err = filepath.Abs(cleanPath)
					if err != nil {
						errs <- fmt.Errorf("failed to get absolute path for %s: %w", fp, err)
						return
					}
				}

				// Read the file
				file, err := os.Open(cleanPath)
				if err != nil {
					errs <- fmt.Errorf("failed to open file %s: %w", fp, err)
					return
				}
				defer func() {
					if cerr := file.Close(); cerr != nil {
						logger.Error("failed to close file", "error", cerr)
					}
				}()

				// Parse the XML
				p := parser.NewXMLParser()
				opnsense, err := p.Parse(file)
				if err != nil {
					errs <- fmt.Errorf("failed to parse XML from %s: %w", fp, err)
					return
				}

				// Convert to markdown
				c := converter.NewMarkdownConverter()
				md, err := c.ToMarkdown(opnsense)
				if err != nil {
					errs <- fmt.Errorf("failed to convert to markdown from %s: %w", fp, err)
					return
				}

				// Determine output path
				actualOutputFile := outputFile
				if len(args) > 1 || (actualOutputFile == "" && Cfg.OutputFile != "") {
					// If multiple files, or single file with no -o but config has output_file
					// use input filename with .md extension
					base := filepath.Base(fp)
					ext := filepath.Ext(base)
					actualOutputFile = strings.TrimSuffix(base, ext) + ".md"
				}

				// Export or print the markdown
				if actualOutputFile != "" {
					e := export.NewFileExporter()
					if err := e.Export(md, actualOutputFile); err != nil {
						errs <- fmt.Errorf("failed to export markdown to %s: %w", actualOutputFile, err)
						return
					}
					logger.Info("Markdown exported", "output_file", actualOutputFile)
				} else {
					logger.Info(md)
				}
			}(filePath)
		}

		wg.Wait()
		close(errs)

		var allErrors error
		for err := range errs {
			if allErrors == nil {
				allErrors = err
			} else {
				allErrors = fmt.Errorf("%w; %w", allErrors, err)
			}
		}

		return allErrors
	},
}
