// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	"github.com/EvilBit-Labs/opnDossier/internal/export"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/spf13/cobra"
)

// auditResult holds the output of a single audit file processing operation,
// pairing the generated report content with the input file path for serialized emission.
type auditResult struct {
	inputFile string
	output    string
}

// emitAuditResult writes a single audit result to the appropriate destination
// (file or stdout). This function must be called serially from the parent
// goroutine to prevent interleaved stdout writes or file clobbering.
// When multiFile is true, per-input auto-named output paths are derived so that
// each input file produces a distinct report file rather than falling back to stdout.
func emitAuditResult(
	ctx context.Context,
	cmd *cobra.Command,
	result auditResult,
	cmdLogger *logging.Logger,
	cmdConfig *config.Config,
	multiFile bool,
) error {
	ctxLogger := cmdLogger.WithContext(ctx).WithFields("input_file", result.inputFile)

	// Build conversion options to determine file extension
	eff := buildEffectiveFormat(format, cmdConfig)
	opt := buildConversionOptions(eff, cmdConfig)

	// Determine file extension from the registry
	handler, err := converter.DefaultRegistry.Get(string(opt.Format))
	if err != nil {
		ctxLogger.Error("format passed validation but registry lookup failed",
			"format", opt.Format, "error", err)

		return fmt.Errorf("internal error determining file extension for %q: %w", opt.Format, err)
	}

	fileExt := handler.FileExtension()

	// For multi-file runs, derive a unique per-input output path so each report
	// goes to its own file. This bypasses the shared config OutputFile (which would
	// cause later reports to overwrite earlier ones) and avoids the stdout fallback
	// (which would interleave reports). The derived path is passed as the explicit
	// outputFile argument to determineOutputPath, giving it CLI-flag precedence.
	perInputOutputFile := outputFile
	if multiFile && outputFile == "" {
		perInputOutputFile = deriveAuditOutputPath(result.inputFile, fileExt)
	}

	// Determine output path with smart naming and overwrite protection.
	// For multi-file runs, pass nil config to prevent the shared config OutputFile
	// from overriding the derived per-input path.
	emitConfig := cmdConfig
	if multiFile {
		emitConfig = nil
	}

	actualOutputFile, err := determineOutputPath(result.inputFile, perInputOutputFile, fileExt, emitConfig, force)
	if err != nil {
		ctxLogger.Error("Failed to determine output path", "error", err)

		return fmt.Errorf("failed to determine output path for %s: %w", result.inputFile, err)
	}

	// Export or print the output
	if actualOutputFile != "" {
		ctxLogger.Debug("Exporting audit report to file", "output_file", actualOutputFile)
		e := export.NewFileExporter(ctxLogger)

		if err := e.Export(ctx, result.output, actualOutputFile); err != nil {
			return fmt.Errorf("failed to export audit report to %s: %w", actualOutputFile, err)
		}
	} else {
		ctxLogger.Debug("Outputting audit report to stdout")

		if _, err := fmt.Fprint(cmd.OutOrStdout(), result.output); err != nil {
			return fmt.Errorf("failed to write audit report to stdout: %w", err)
		}
	}

	return nil
}

// deriveAuditOutputPath computes a unique output filename for a multi-file audit
// run based on the input file's path and the desired format extension.
// Directory separators are losslessly encoded using tilde-based escaping: tildes
// in path segments become "~~" and underscores become "~u", freeing the literal
// underscore character to serve as an unambiguous segment separator. This avoids
// the boundary ambiguity of the simpler double-underscore scheme, where a segment
// ending with "_" followed by the separator is indistinguishable from the separator
// followed by a segment starting with "_" (e.g., "a_/b" and "a/_b" both producing
// "a___b"). Bare filenames without directory components produce simple names like
// "config-audit.md".
func deriveAuditOutputPath(inputFile, fileExt string) string {
	base := filepath.Base(inputFile)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	const absolutePathMarker = "~a"

	dir := filepath.Dir(inputFile)
	if dir != "" && dir != "." {
		cleaned := filepath.Clean(dir)
		isAbs := filepath.IsAbs(cleaned)

		if isAbs {
			cleaned = strings.TrimPrefix(cleaned, string(filepath.Separator))
		}

		rawSegments := strings.Split(cleaned, string(filepath.Separator))
		segments := make([]string, 0, len(rawSegments)+1)

		if isAbs {
			segments = append(segments, absolutePathMarker)
		}

		for _, seg := range rawSegments {
			if seg == "" {
				continue
			}

			segments = append(segments, escapePathSegment(seg))
		}

		escapedStem := escapePathSegment(stem)
		prefix := strings.Join(segments, "_")

		return prefix + "_" + escapedStem + "-audit" + fileExt
	}

	escapedStem := escapePathSegment(stem)

	return escapedStem + "-audit" + fileExt
}

// escapePathSegment encodes a single path segment for use in a flattened filename.
// Tildes are escaped as "~~" and underscores as "~u", making the underscore
// character available as an unambiguous segment separator in the flattened name.
// This avoids the boundary ambiguity of double-underscore escaping where segment
// "a_" + separator + "b" and segment "a" + separator + "_b" both flatten to "a___b".
func escapePathSegment(seg string) string {
	s := strings.ReplaceAll(seg, "~", "~~")
	s = strings.ReplaceAll(s, "_", "~u")

	return s
}
