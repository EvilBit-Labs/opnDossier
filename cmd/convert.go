// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"text/template"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/export"
	"github.com/EvilBit-Labs/opnDossier/internal/log"
	"github.com/EvilBit-Labs/opnDossier/internal/markdown"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/parser"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	outputFile string //nolint:gochecknoglobals // Cobra flag variable
	format     string //nolint:gochecknoglobals // Output format (markdown, json, yaml)
	force      bool   //nolint:gochecknoglobals // Force overwrite without prompt
)

// TemplateCache provides thread-safe LRU caching for template instances.
// It caches templates by path to avoid redundant file I/O and parsing operations.
// The cache uses LRU eviction with a configurable maximum size to prevent memory growth.
//
// Cache Behavior and Limits:
// - Thread-safe: All operations are safe for concurrent access
// - LRU Eviction: When the cache reaches its maximum size, the least recently used template is automatically evicted
// - Configurable Size: Default is 10 templates, can be configured via --template-cache-size flag
// - Memory Management: Templates are automatically evicted to prevent unbounded memory growth
// - Batch Operations: Cache is cleared after each batch operation to free memory
//
// Usage:
// - For single file operations: Cache size of 1-5 is sufficient
// - For batch operations: Cache size of 10-20 provides good performance
// - For memory-constrained environments: Use smaller cache sizes (1-5)
// - For high-performance scenarios: Use larger cache sizes (20-50).
type TemplateCache struct {
	cache *lru.Cache[string, *template.Template]
}

// NewTemplateCache creates a new template cache instance with LRU eviction using hashicorp/golang-lru/v2.
// The cache will automatically evict least recently used templates when the max size is reached.
// Default max size is 10 templates to balance memory usage with performance.
// Errors are returned to allow callers to handle invalid configuration gracefully.
func NewTemplateCache() (*TemplateCache, error) {
	cache, err := NewTemplateCacheWithSize(defaultTemplateCacheSize)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create template cache with default size %d: %w",
			defaultTemplateCacheSize,
			err,
		)
	}
	return cache, nil
}

// NewTemplateCacheWithSize creates a new template cache instance with a specified maximum size.
// The cache will automatically evict least recently used templates when the max size is reached.
// Size must be greater than 0; returns ErrInvalidCacheSize if size is invalid.
func NewTemplateCacheWithSize(size int) (*TemplateCache, error) {
	if size <= 0 {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidCacheSize, size)
	}

	// Create LRU cache with specified max size
	cache, err := lru.New[string, *template.Template](size)
	if err != nil {
		return nil, fmt.Errorf("failed to create LRU cache: %w", err)
	}

	return &TemplateCache{
		cache: cache,
	}, nil
}

// Get retrieves a template from the cache, loading it if not present.
// Returns the cached template or an error if loading fails.
// Thread-safe and uses LRU eviction when cache is full.
func (tc *TemplateCache) Get(templatePath string) (*template.Template, error) {
	if templatePath == "" {
		return nil, ErrNoTemplateSpecified
	}

	// Check cache first
	if tmpl, exists := tc.cache.Get(templatePath); exists {
		return tmpl, nil
	}

	// Load template if not in cache
	tmpl, err := loadCustomTemplate(templatePath)
	if err != nil {
		return nil, err
	}

	// Cache the template (LRU will handle eviction if needed)
	tc.cache.Add(templatePath, tmpl)
	return tmpl, nil
}

// Clear removes all cached templates, freeing memory.
// This is useful between batch operations to prevent memory growth.
func (tc *TemplateCache) Clear() {
	tc.cache.Purge()
}

// Size returns the number of cached templates.
func (tc *TemplateCache) Size() int {
	return tc.cache.Len()
}

// ErrOperationCancelled is returned when the user cancels an operation.
var ErrOperationCancelled = errors.New("operation cancelled by user")

// Static errors for better error handling.
var (
	ErrFailedToEnrichConfig    = errors.New("failed to enrich configuration")
	ErrNoTemplateSpecified     = errors.New("no template specified")
	ErrInvalidCacheSize        = errors.New("template cache size must be greater than 0")
	ErrUnsupportedOutputFormat = errors.New("unsupported output format")
	ErrUnknownEngineType       = errors.New("unknown engine type")
)

// Format constants for output formats.
const (
	FormatMarkdown = "markdown"
	FormatJSON     = "json"
	FormatYAML     = "yaml"
)

// DefaultTemplateCacheSize is the default maximum number of templates to cache in memory.
// This provides a good balance between memory usage and performance for most use cases.
const DefaultTemplateCacheSize = 10

// defaultTemplateCacheSize allows tests to simulate invalid defaults.
var defaultTemplateCacheSize = DefaultTemplateCacheSize //nolint:gochecknoglobals // test override hook

// init registers the convert command and its flags with the root command.
//
// This function sets up command-line flags for output file path, format, template, sections, theme, and text wrap width, enabling users to customize the conversion of OPNsense configuration files.
func init() {
	rootCmd.AddCommand(convertCmd)

	// Output and format flags
	convertCmd.Flags().
		StringVarP(&outputFile, "output", "o", "", "Output file path for saving converted configuration (default: print to console)")
	setFlagAnnotation(convertCmd.Flags(), "output", []string{"output"})
	convertCmd.Flags().
		StringVarP(&format, "format", "f", "markdown", "Output format for conversion (markdown, json, yaml)")
	setFlagAnnotation(convertCmd.Flags(), "format", []string{"output"})
	convertCmd.Flags().
		BoolVar(&force, "force", false, "Force overwrite existing files without prompting for confirmation")
	setFlagAnnotation(convertCmd.Flags(), "force", []string{"output"})

	// Add shared template flags
	addSharedTemplateFlags(convertCmd)

	// Flag groups for better organization
	convertCmd.Flags().SortFlags = false
}

var convertCmd = &cobra.Command{ //nolint:gochecknoglobals // Cobra command
	Use:     "convert [file ...]",
	Short:   "Convert OPNsense configuration files to structured formats.",
	GroupID: "core",
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		// Validate flag combinations specific to convert command
		if err := validateConvertFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("convert command validation failed: %w", err)
		}

		return nil
	},
	Long: `The 'convert' command processes one or more OPNsense config.xml files and transforms
its content into structured formats. Supported output formats include Markdown (default),
JSON, and YAML. This allows for easier readability, documentation, and programmatic access
to your firewall configuration.

  NEW in Phase 3.7: The convert command now uses programmatic generation by default for
  improved performance and security. Template-based generation is available via explicit flags.

  GENERATION MODES:
  The convert command supports two generation modes:

  Programmatic mode (default):
    - Fast, secure, and deterministic output generation
    - No template file I/O operations required
    - Enhanced error handling and validation
    - Recommended for most use cases

  Template mode (explicit):
    --use-template                  - Use built-in template generation
    --custom-template FILE          - Use custom template file (auto-enables template mode)
    --engine template               - Explicitly select template engine
    --legacy                        - Enable legacy template mode (deprecated)

  Additional options:
    --comprehensive                 - Generate detailed, comprehensive reports

  OUTPUT FORMATS:
  The convert command supports multiple output formats:

  Basic formats (use --format flag):
    markdown                    - Standard markdown report (default)
    json                        - JSON format output
    yaml                        - YAML format output

  Use --format for basic output formats (markdown, json, yaml).

The convert command focuses on conversion only and does not perform validation.
To validate your configuration files before conversion, use the 'validate' command.

You can either print the generated output directly to the console or save it to a
specified output file using the '--output' or '-o' flag. Use the '--format' or '-f'
flag to specify the output format (markdown, json, or yaml).

When processing multiple files, the --output flag will be ignored, and each output
file will be named based on its input file with the appropriate extension
(e.g., config.xml -> config.md, config.json, or config.yaml).

Examples:
  # Convert using programmatic mode (default, fastest)
  opnDossier convert my_config.xml

  # Convert with explicit engine selection
  opnDossier convert my_config.xml --engine programmatic
  opnDossier convert my_config.xml --engine template

  # Convert 'my_config.xml' to JSON format
  opnDossier convert my_config.xml --format json

  # Convert 'my_config.xml' to YAML and save to file
  opnDossier convert my_config.xml -f yaml -o documentation.yaml

  # Generate comprehensive report (programmatic mode)
  opnDossier convert my_config.xml --comprehensive

  # Use template mode explicitly
  opnDossier convert my_config.xml --use-template

  # Use custom template (automatically enables template mode)
  opnDossier convert my_config.xml --custom-template /path/to/my-template.tmpl

  # Legacy template mode (deprecated, will show warning)
  opnDossier convert my_config.xml --legacy

  # Convert with specific sections
  opnDossier convert my_config.xml --section system,network

  # Convert with format and text wrapping
  opnDossier convert my_config.xml --format json --wrap 120

  # Convert without text wrapping
  opnDossier convert my_config.xml --no-wrap

  # Convert multiple files to JSON format
  opnDossier convert config1.xml config2.xml --format json

  # Convert 'backup_config.xml' with verbose logging
  opnDossier --verbose convert backup_config.xml -f json

  # Use environment variable to set default output location
  OPNDOSSIER_OUTPUT_FILE=./docs/network.md opnDossier convert config.xml

  # Force overwrite existing file without prompt
  opnDossier convert config.xml -o output.md --force

  # Include all system tunables (including defaults) in the report
  opnDossier convert config.xml --include-tunables

  # Validate before converting (recommended workflow)
  opnDossier validate config.xml && opnDossier convert config.xml -f json -o output.json

  MIGRATION GUIDE:
  If you were using template mode previously, add --use-template to maintain compatibility:
  opnDossier convert config.xml --use-template --comprehensive`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		var wg sync.WaitGroup
		errs := make(chan error, len(args))

		// Create a timeout context for file processing
		timeoutCtx, cancel := context.WithTimeout(ctx, constants.DefaultProcessingTimeout)
		defer cancel()

		// Create template cache for batch processing with configurable size.
		// If cache creation fails, return the error to allow CLI-level reporting.
		templateCache, err := NewTemplateCacheWithSize(sharedTemplateCacheSize)
		if err != nil {
			return fmt.Errorf(
				"failed to create template cache with size %d (must be > 0, recommended: %d-%d): %w",
				sharedTemplateCacheSize, 1, MaxTemplateCacheSize, err)
		}
		defer templateCache.Clear() // Clean up cache after processing

		// Validate custom template path if specified (early validation)
		if sharedCustomTemplate != "" {
			if err := validateTemplatePath(sharedCustomTemplate); err != nil {
				return fmt.Errorf("template validation failed: %w", err)
			}
		}

		// Preload the custom template if specified
		var cachedTemplate *template.Template
		if sharedCustomTemplate != "" {
			var err error
			cachedTemplate, err = templateCache.Get(sharedCustomTemplate)
			if err != nil {
				// ErrNoTemplateSpecified shouldn't occur here since sharedCustomTemplate is not empty,
				// but we check defensively. Any other error is a real problem.
				if !errors.Is(err, ErrNoTemplateSpecified) {
					return fmt.Errorf("failed to preload custom template %q: %w "+
						"(check that the file exists, is readable, and contains valid template syntax)",
						sharedCustomTemplate, err)
				}
				// If we somehow get ErrNoTemplateSpecified when sharedCustomTemplate is set,
				// this indicates a programming error in templateCache.Get
				logger.Warn("unexpected ErrNoTemplateSpecified when template path is set",
					"template", sharedCustomTemplate)
			}
		}

		for _, filePath := range args {
			wg.Add(1)
			go func(fp string) {
				defer wg.Done()

				// Create context-aware logger for this goroutine with input file field
				ctxLogger := logger.WithContext(timeoutCtx).WithFields("input_file", fp)

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
						ctxLogger.Error("failed to close file", "error", cerr)
					}
				}()

				// Parse the XML without validation (use 'validate' command for validation)
				ctxLogger.Debug("Parsing XML file")
				p := parser.NewXMLParser()
				opnsense, err := p.Parse(timeoutCtx, file)
				if err != nil {
					ctxLogger.Error("Failed to parse XML", "error", err)
					// Enhanced error handling for different error types
					if parser.IsParseError(err) {
						if parseErr := parser.GetParseError(err); parseErr != nil {
							ctxLogger.Error(
								"XML syntax error detected",
								"line",
								parseErr.Line,
								"message",
								parseErr.Message,
							)
						}
					}
					if parser.IsValidationError(err) {
						ctxLogger.Error("Configuration validation failed")
					}
					errs <- fmt.Errorf("failed to parse XML from %s: %w", fp, err)
					return
				}
				ctxLogger.Debug("XML parsing completed successfully")

				// Build options for conversion with precedence: CLI flags > env vars > config > defaults
				eff := buildEffectiveFormat(format, Cfg)
				opt := buildConversionOptions(eff, Cfg)

				// Convert using the new markdown generator
				var output string
				var fileExt string

				ctxLogger.Debug(
					"Converting with options",
					"format",
					opt.Format,
					"theme",
					opt.Theme,
					"sections",
					opt.Sections,
				)

				// Generate output based on format using the cached template
				output, err = generateOutputByFormat(timeoutCtx, opnsense, opt, ctxLogger, cachedTemplate)
				if err != nil {
					ctxLogger.Error("Failed to convert", "error", err)
					errs <- fmt.Errorf("failed to convert from %s: %w", fp, err)
					return
				}

				// Determine file extension based on format
				switch strings.ToLower(string(opt.Format)) {
				case "markdown", "md":
					fileExt = ".md"
				case "json":
					fileExt = ".json"
				case "yaml", "yml":
					fileExt = ".yaml"
				default:
					fileExt = ".md" // Default to markdown
				}

				ctxLogger.Debug("Conversion completed successfully")

				// Determine output path with smart naming and overwrite protection
				actualOutputFile, err := determineOutputPath(fp, outputFile, fileExt, Cfg, force)
				if err != nil {
					ctxLogger.Error("Failed to determine output path", "error", err)
					errs <- fmt.Errorf("failed to determine output path for %s: %w", fp, err)
					return
				}

				// Create enhanced logger with output file information
				var enhancedLogger *log.Logger
				if actualOutputFile != "" {
					enhancedLogger = ctxLogger.WithFields("output_file", actualOutputFile)
				} else {
					enhancedLogger = ctxLogger.WithFields("output_mode", "stdout")
				}

				// Export or print the output
				if actualOutputFile != "" {
					enhancedLogger.Debug("Exporting to file")
					e := export.NewFileExporter(ctxLogger)
					if err := e.Export(timeoutCtx, output, actualOutputFile); err != nil {
						enhancedLogger.Error("Failed to export output", "error", err)
						errs <- fmt.Errorf("failed to export output to %s: %w", actualOutputFile, err)
						return
					}
					// Output exported successfully (no logging to avoid corrupting output)
				} else {
					enhancedLogger.Debug("Outputting to stdout")
					fmt.Print(output)
				}

				// Conversion process completed successfully (no logging to avoid corrupting output)
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

// buildEffectiveFormat returns the output format to use, giving precedence to the CLI flag, then the configuration file, and defaulting to "markdown" if neither is set.
func buildEffectiveFormat(flagFormat string, cfg *config.Config) string {
	// CLI flag takes precedence
	if flagFormat != "" {
		return flagFormat
	}

	// Use config value if CLI flag not specified
	if cfg != nil && cfg.GetFormat() != "" {
		return cfg.GetFormat()
	}

	// Default
	return "markdown"
}

// buildConversionOptions constructs a markdown.Options struct by merging CLI arguments and configuration values with defined precedence.
// CLI arguments take priority over configuration file values, which in turn override defaults. The resulting options control output format, template, section filtering, theme, and text wrapping for the conversion process.
func buildConversionOptions(
	format string,
	cfg *config.Config,
) markdown.Options {
	// Start with defaults
	opt := markdown.DefaultOptions()

	// Set format
	opt.Format = markdown.Format(format)

	// Propagate quiet flag to suppress deprecation warnings
	if cfg != nil && cfg.IsQuiet() {
		opt.SuppressWarnings = true
	}

	// Template: config > default (no CLI flag for template)
	if cfg != nil && cfg.GetTemplate() != "" {
		opt.TemplateName = cfg.GetTemplate()
	}

	// Sections: CLI flag > config > default
	if len(sharedSections) > 0 {
		opt.Sections = sharedSections
	} else if cfg != nil && len(cfg.GetSections()) > 0 {
		opt.Sections = cfg.GetSections()
	}

	// Theme: config > default (no CLI flag for theme in convert command)
	if cfg != nil && cfg.GetTheme() != "" {
		opt.Theme = markdown.Theme(cfg.GetTheme())
	}

	// Wrap width: CLI flag > config > default
	// -1 means auto-detect (not provided), 0 means no wrapping, >0 means specific width
	// Config values of -1 are treated as "not set" and fall through to default
	switch {
	case sharedWrapWidth >= 0:
		opt.WrapWidth = sharedWrapWidth
	case cfg != nil && cfg.GetWrapWidth() >= 0:
		opt.WrapWidth = cfg.GetWrapWidth()
	default:
		opt.WrapWidth = -1
	}

	// Comprehensive: CLI flag only
	opt.Comprehensive = sharedComprehensive

	// Template directory: CLI flag only
	templateDir := getSharedTemplateDir()
	if templateDir != "" {
		opt.TemplateDir = templateDir
	}

	// Include tunables: CLI flag only
	opt.CustomFields["IncludeTunables"] = sharedIncludeTunables

	// Engine selection: CLI flags > config > default
	opt.UseTemplateEngine = determineUseTemplateFromConfig(cfg)

	return opt
}

// determineUseTemplateFromConfig determines if template mode should be used based on configuration.
// This provides a fallback for configuration-based engine selection when CLI flags aren't used.
func determineUseTemplateFromConfig(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}

	// Check configuration engine setting
	if cfg.GetEngine() != "" {
		return strings.EqualFold(cfg.GetEngine(), "template")
	}

	// Check configuration use_template setting
	if cfg.IsUseTemplate() {
		return true
	}

	// Default to programmatic mode
	return false
}

// determineOutputPath determines the output file path with smart naming and overwrite protection.
// It handles the following scenarios:
// 1. If outputFile is specified, use it (with overwrite protection)
// 2. If multiple files are being processed, use input filename with appropriate extension
// 3. If config has output_file but no CLI flag, use input filename with appropriate extension
// 4. If no output specified, return empty string (stdout)
//
// The function ensures no automatic directory creation and provides overwrite prompts
// unless the force flag is set.
func determineOutputPath(inputFile, outputFile, fileExt string, cfg *config.Config, force bool) (string, error) {
	// If no output file specified, return empty string for stdout
	if outputFile == "" && (cfg == nil || cfg.OutputFile == "") {
		return "", nil
	}

	var actualOutputFile string

	// Determine the output file path using switch statement
	switch {
	case outputFile != "":
		// CLI flag takes precedence
		actualOutputFile = outputFile
	case cfg != nil && cfg.OutputFile != "":
		// Use config value if CLI flag not specified
		actualOutputFile = cfg.OutputFile
	default:
		// Use input filename with appropriate extension as default
		base := filepath.Base(inputFile)
		ext := filepath.Ext(base)
		actualOutputFile = strings.TrimSuffix(base, ext) + fileExt
	}

	// Check if file already exists and handle overwrite protection
	if _, err := os.Stat(actualOutputFile); err == nil {
		// File exists, check if we should overwrite
		if !force {
			// Prompt user for confirmation (using stderr to avoid interfering with piped output)
			fmt.Fprintf(os.Stderr, "File '%s' already exists. Overwrite? (y/N): ", actualOutputFile)

			// Use bufio.NewReader to correctly capture entire input line including spaces
			reader := bufio.NewReader(os.Stdin)

			response, err := reader.ReadString('\n')
			if err != nil {
				return "", fmt.Errorf("failed to read user input: %w", err)
			}

			// Trim whitespace and newline characters
			response = strings.TrimSpace(response)

			// Empty input defaults to "N" (no)
			if response == "" {
				response = "N"
			}

			// Only proceed if user explicitly confirms with 'y' or 'Y'
			if response != "y" && response != "Y" {
				return "", ErrOperationCancelled
			}
		}
	}

	return actualOutputFile, nil
}

// generateOutputByFormat generates output using the appropriate generator based on the format.
func generateOutputByFormat(
	ctx context.Context,
	opnsense *model.OpnSenseDocument,
	opt markdown.Options,
	logger *log.Logger,
	preParsedTemplate *template.Template,
) (string, error) {
	// Determine the format to use
	format := strings.ToLower(string(opt.Format))

	switch format {
	case FormatMarkdown, "md":
		// Use hybrid generator for markdown output
		return generateWithHybridGenerator(ctx, opnsense, opt, logger, preParsedTemplate)
	case FormatJSON, FormatYAML, "yml":
		// Use markdown generator for JSON and YAML output
		// The markdown generator supports JSON and YAML formats natively
		// Set the format in options
		opt.Format = markdown.Format(format)
		generator, err := markdown.NewMarkdownGenerator(logger, opt)
		if err != nil {
			return "", fmt.Errorf("failed to create markdown generator: %w", err)
		}
		return generator.Generate(ctx, opnsense, opt)
	default:
		return "", fmt.Errorf("%w: %q (supported: markdown, md, json, yaml, yml)", ErrUnsupportedOutputFormat, format)
	}
}

// generateWithHybridGenerator creates a hybrid generator and generates output using either
// programmatic generation (default) or template generation based on options.
// If a pre-parsed template is provided, it will be used instead of loading from file.
func generateWithHybridGenerator(
	ctx context.Context,
	opnsense *model.OpnSenseDocument,
	opt markdown.Options,
	logger *log.Logger,
	preParsedTemplate *template.Template,
) (string, error) {
	// Determine generation engine based on CLI flags and configuration
	useTemplateEngine, err := determineGenerationEngine(logger)
	if err != nil {
		return "", fmt.Errorf("failed to determine generation engine: %w", err)
	}

	// Update opt.UseTemplateEngine to reflect CLI flag precedence
	// This ensures CLI flags take precedence over config file settings
	opt.UseTemplateEngine = useTemplateEngine

	// Create the programmatic builder
	builder := converter.NewMarkdownBuilder()

	// Create hybrid generator
	hybridGen, err := markdown.NewHybridGenerator(builder, logger)
	if err != nil {
		return "", fmt.Errorf("failed to create hybrid generator: %w", err)
	}

	// Set template if using template engine and a pre-parsed template is available
	if useTemplateEngine && preParsedTemplate != nil {
		hybridGen.SetTemplate(preParsedTemplate)
	}

	// Override the hybrid generator's shouldUseTemplate logic by modifying options
	// This ensures our CLI-based engine selection takes precedence
	// We intentionally override the generator's hybrid-mode detection by setting TemplateName/TemplateDir
	// to force either template mode (using shared custom or built-in default) or programmatic mode (clearing both),
	// so the hybrid generator doesn't auto-select the wrong mode based on useTemplateEngine and sharedCustomTemplate conditions.
	if useTemplateEngine {
		// Force template mode if CLI flags indicate template usage
		if sharedCustomTemplate != "" {
			opt.TemplateDir = getSharedTemplateDir()
		} else {
			// Use built-in templates for legacy/use-template modes
			opt.TemplateName = "default"
		}
	} else {
		// Force programmatic mode by clearing template-related options
		opt.TemplateName = ""
		opt.TemplateDir = ""
	}

	// Generate the output
	return hybridGen.Generate(ctx, opnsense, opt)
}

// loadCustomTemplate loads a custom template from a file.
func loadCustomTemplate(templatePath string) (*template.Template, error) {
	// Read the template file
	content, err := os.ReadFile(templatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("template file not found: %s. "+
				"Check that the path is correct and the file exists", templatePath)
		}
		if os.IsPermission(err) {
			return nil, fmt.Errorf("permission denied reading template file: %s. "+
				"Check file permissions", templatePath)
		}
		return nil, fmt.Errorf("failed to read template file %s: %w. "+
			"Check that the file is accessible and not corrupted", templatePath, err)
	}

	// Parse the template
	tmpl, err := template.New("custom").Parse(string(content))
	if err != nil {
		return nil, fmt.Errorf("failed to parse template %s: %w. "+
			"Check template syntax - see https://pkg.go.dev/text/template for syntax reference",
			templatePath, err)
	}

	return tmpl, nil
}

// validateConvertFlags validates flag combinations specific to the convert command.
func validateConvertFlags(flags *pflag.FlagSet) error {
	// Validate mutual exclusivity for wrap flags before other checks
	if flags != nil {
		noWrapFlag := flags.Lookup("no-wrap")
		wrapFlag := flags.Lookup("wrap")
		if noWrapFlag != nil && wrapFlag != nil && noWrapFlag.Changed && wrapFlag.Changed {
			return errors.New("--no-wrap and --wrap flags are mutually exclusive")
		}
	}

	if sharedNoWrap {
		sharedWrapWidth = 0
	}

	// Validate format values
	if format != "" {
		validFormats := []string{"markdown", "md", "json", "yaml", "yml"}
		if !slices.Contains(validFormats, strings.ToLower(format)) {
			return fmt.Errorf("invalid format %q, must be one of: %s", format, strings.Join(validFormats, ", "))
		}
	}

	// Validate engine flag combinations
	if sharedEngine != "" {
		if sharedUseTemplate {
			return errors.New("--use-template and --engine flags are mutually exclusive")
		}
		if sharedLegacy {
			return errors.New("--legacy and --engine flags are mutually exclusive")
		}
		if sharedCustomTemplate != "" {
			return errors.New(
				"--custom-template and --engine flags are mutually exclusive when engine is explicitly set",
			)
		}
	}

	// Validate template-related flags
	if sharedCustomTemplate != "" && sharedUseTemplate {
		return errors.New("--custom-template automatically enables template mode, --use-template is redundant")
	}

	// Validate output format compatibility
	if strings.EqualFold(format, "json") && len(sharedSections) > 0 {
		logger.Warn("section filtering not supported with JSON format, sections will be ignored")
	}
	if strings.EqualFold(format, "yaml") && len(sharedSections) > 0 {
		logger.Warn("section filtering not supported with YAML format, sections will be ignored")
	}

	// Validate wrap width if specified
	if sharedWrapWidth > 0 && (sharedWrapWidth < MinWrapWidth || sharedWrapWidth > MaxWrapWidth) {
		return fmt.Errorf("wrap width %d out of recommended range [%d, %d]",
			sharedWrapWidth, MinWrapWidth, MaxWrapWidth)
	}

	// Validate template cache size if specified
	if sharedTemplateCacheSize > MaxTemplateCacheSize {
		return fmt.Errorf("template cache size %d exceeds maximum recommended size %d",
			sharedTemplateCacheSize, MaxTemplateCacheSize)
	}

	return nil
}
